#!/usr/bin/env python3
"""Garde-fou de la vitrine : bloque tout fichier qui contient une valeur sensible.

Vérifie chaque fichier qui partirait dans le dépôt (suivi, ou non suivi et non ignoré) :
- texte : la liste noire (hors dépôt) et des règles génériques (IP hors plages de
  documentation, MAC, e-mails, domaines internes, clés) ;
- images : le texte lu par OCR, et l'absence de métadonnées ;
- vidéos : l'OCR de plusieurs images par seconde, les métadonnées, l'absence de piste audio.

Usage :
    tools/check_leaks.py              # tout le dépôt
    tools/check_leaks.py --staged     # en plus, la version indexée des fichiers (pré-commit)
    tools/check_leaks.py --generic-only   # sans liste noire (CI publique)
    tools/check_leaks.py --every-frame    # OCR de chaque image des vidéos (avant publication)
    tools/check_leaks.py --history        # en plus, tout l'historique git (messages et diffs)

Codes de sortie : 0 rien trouvé, 1 fuite trouvée, 2 erreur de configuration.
Les valeurs trouvées sont masquées à l'affichage, sauf avec --show (terminal local seulement).
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BLACKLIST = Path("~/.config/homelab_demo/liste-noire.txt")
CACHE_DIR = Path(os.environ.get("HOMELAB_DEMO_CACHE", "~/.cache/homelab_demo/ocr"))

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
VIDEO_EXT = {".mp4", ".webm", ".mov", ".mkv", ".gif", ".avi"}
BINARY_SKIP_EXT = {".ico", ".woff", ".woff2", ".ttf", ".otf"}

# Plages réservées à la documentation : les seules adresses autorisées dans la vitrine.
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
DOC_MAC_PREFIX = "00:00:5e:00:53:"  # RFC 7042
ALLOWED_EMAIL_DOMAINS = re.compile(
    r"@(?:[\w-]+\.)*(?:exemple\.lab|example\.(?:com|org|net)|users\.noreply\.github\.com)$", re.I)
NOREPLY_RE = re.compile(r"@users\.noreply\.github\.com$", re.I)

IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w]|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9a-fA-F]{1,4}:|:){2,7}[0-9a-fA-F]{0,4})(?![\w:])")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
WG_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])")
GENERIC_RULES = [
    ("domaine interne", re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:internal|lan|local|home\.arpa|localdomain)\b(?!\.\w)", re.I)),
    ("nom OVH", re.compile(r"\b(?:ns\d{5,}|ftpback-[\w-]+|ip-\d{1,3}-\d{1,3}-\d{1,3}(?:-\d{1,3})?)\b", re.I)),
    ("domaine OVH", re.compile(r"\b[\w-]+\.(?:ovh\.net|ip-[\d-]+\.eu|kimsufi\.com)\b", re.I)),
    ("clé SSH", re.compile(r"\b(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)\s+AAAA[A-Za-z0-9+/=]{20,}")),
    ("empreinte", re.compile(r"\bSHA256:[A-Za-z0-9+/]{43}\b")),
    ("clé privée", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bPrivateKey\s*=\s*\S")),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
]

# Blocs PNG sans information personnelle (densité de pixels, gamma, espace colorimétrique).
HARMLESS_IMAGE_GROUPS = ("PNG-pHYs:", "PNG-gAMA:", "PNG-sRGB:", "PNG-cHRM:", "PNG-bKGD:")

# Signatures que les encodeurs inscrivent dans le flux lui-même, invisibles pour ffprobe.
ENCODER_SIGNATURE_RE = re.compile(rb"x264 - core|x265 \(build|Lavf\d|Lavc\d|HandBrake|OBS Studio|obs-output")

# Métadonnées tolérées dans une vidéo : la structure du conteneur, rien d'autre.
ALLOWED_VIDEO_TAGS = {"major_brand", "minor_version", "compatible_brands", "language",
                      "handler_name", "vendor_id"}


@dataclass
class Finding:
    path: str
    where: str
    rule: str
    value: str


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return f"[{len(value)} caractères]"
    return f"{value[:2]}{'•' * (len(value) - 4)}{value[-2:]}"


# ---------------------------------------------------------------- liste noire

def compile_entry(entry: str) -> tuple[str, re.Pattern] | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    if entry.startswith("re:"):
        return entry, re.compile(entry[3:], re.I)
    if entry.startswith("port:"):
        n = int(entry[5:])
        if n >= 1000:
            return entry, re.compile(rf"(?<![\w.]){n}(?![\w])")
        return entry, re.compile(
            rf"(?:(?<=[A-Za-z\]]):{n}\b|\b{n}/(?:tcp|udp)\b|\bports?\s+{n}\b"
            rf"|\b(?:dport|sport|ListenPort|Port)\s*=?\s*{n}\b)", re.I)
    body = r"\s+".join(re.escape(part) for part in entry.split())
    return entry, re.compile(rf"(?<!\w){body}(?!\w)", re.I)


def load_blacklist(path: Path) -> list[tuple[str, re.Pattern]]:
    rules = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        try:
            compiled = compile_entry(line)
        except (re.error, ValueError) as e:
            raise SystemExit(f"Liste noire, ligne {n} invalide : {e}")
        if compiled:
            rules.append(compiled)
    if len(rules) < 10:
        raise SystemExit(f"Liste noire presque vide ({len(rules)} entrées) : refus par prudence.")
    return rules


# ---------------------------------------------------------------- texte

def is_doc_ip(addr) -> bool:
    return any(addr.version == net.version and addr in net for net in DOC_NETS)


def generic_findings(text: str) -> list[tuple[int, str, str]]:
    """(position, règle, valeur) pour chaque valeur interdite quelle que soit la liste noire."""
    out = []
    for m in IPV4_RE.finditer(text):
        try:
            addr = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        generic = addr.is_loopback or addr.is_unspecified or m.group(1).startswith("255.")
        if not generic and not is_doc_ip(addr):
            out.append((m.start(), "IPv4 hors plage de documentation", m.group(1)))
    for m in IPV6_RE.finditer(text):
        raw = m.group(1)
        if raw.count(":") < 2 or len([g for g in raw.split(":") if g]) < 3:
            continue  # « ::5 » ou « a[::5] » : trop court pour être une adresse réelle
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_unspecified or is_doc_ip(addr)):
            out.append((m.start(), "IPv6 hors plage de documentation", raw))
    for m in MAC_RE.finditer(text):
        if not m.group(1).lower().replace("-", ":").startswith(DOC_MAC_PREFIX):
            out.append((m.start(), "adresse MAC", m.group(1)))
    for m in EMAIL_RE.finditer(text):
        if not ALLOWED_EMAIL_DOMAINS.search(m.group(0)):
            out.append((m.start(), "adresse e-mail", m.group(0)))
    for m in WG_KEY_RE.finditer(text):
        out.append((m.start(), "clé WireGuard", m.group(0)))
    for name, rx in GENERIC_RULES:
        for m in rx.finditer(text):
            out.append((m.start(), name, m.group(0)))
    return out


def ocr_variant(text: str) -> str:
    """Corrige les confusions classiques de l'OCR dans les nombres (O/0, l/1…)."""
    def fix(m):
        return m.group(0).translate(str.maketrans("OoQDIl|SB", "000011158"))
    return re.sub(r"[\dOoQDIl|SB][\dOoQDIl|SB.:/-]{3,}", fix, text)


def scan_text(path: str, text: str, blacklist, label="ligne") -> list[Finding]:
    found = []
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def where(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return f"{label} {lo + 1}"

    for pos, rule, value in generic_findings(text):
        found.append(Finding(path, where(pos), rule, value))
    for entry, rx in blacklist:
        for m in rx.finditer(text):
            found.append(Finding(path, where(m.start()), "liste noire", m.group(0)))
    return found


# ---------------------------------------------------------------- médias

def require(tool: str):
    if not shutil.which(tool):
        raise SystemExit(f"Outil manquant : {tool}. Le contrôle des médias est impossible, refus.")


def ocr(image: Path) -> str:
    texts = []
    for psm in ("3", "11"):  # page entière, puis texte épars (interfaces)
        r = subprocess.run(["tesseract", str(image), "-", "-l", "fra+eng", "--psm", psm],
                           capture_output=True, text=True)
        texts.append(r.stdout)
    return "\n".join(texts)


def upscale(src: Path, dst: Path):
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(src), "-frames:v", "1",
                    "-vf", "scale=iw*2:ih*2:flags=lanczos", str(dst)], check=True)


def cached(key: str, compute) -> str:
    cache = CACHE_DIR.expanduser()
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o700)
    f = cache / f"{key}.txt"
    if f.exists():
        return f.read_text()
    text = compute()
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(text)
    return text


def image_metadata_findings(path: str, file: Path) -> list[Finding]:
    """Toute balise qui disparaît quand on vide les métadonnées est une métadonnée restante."""
    def tags(p: Path) -> dict:
        r = subprocess.run(["exiftool", "-j", "-a", "-G1", "-n", str(p)], capture_output=True, text=True)
        data = json.loads(r.stdout or "[{}]")[0]
        return {k: v for k, v in data.items() if not k.startswith(("System:", "ExifTool:", "File:", "SourceFile"))}

    with tempfile.TemporaryDirectory() as tmp:
        stripped = Path(tmp) / f"vide{file.suffix}"
        subprocess.run(["exiftool", "-q", "-all=", "-o", str(stripped), str(file)], capture_output=True)
        before = tags(file)
        after = tags(stripped) if stripped.exists() else {}
    extra = sorted(k for k in set(before) - set(after) if not k.startswith(HARMLESS_IMAGE_GROUPS))
    return [Finding(path, "métadonnées", "métadonnée restante", ", ".join(extra))] if extra else []


def video_metadata_findings(path: str, file: Path) -> list[Finding]:
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format_tags:stream_tags:stream=codec_type",
                        "-of", "json", str(file)], capture_output=True, text=True)
    data = json.loads(r.stdout or "{}")
    found = []
    tags = dict(data.get("format", {}).get("tags", {}))
    for stream in data.get("streams", []):
        tags.update(stream.get("tags", {}))
        if stream.get("codec_type") == "audio" and file.suffix != ".gif":
            found.append(Finding(path, "pistes", "piste audio", "la vidéo doit être muette"))
    extra = sorted(k for k in tags if k.lower() not in ALLOWED_VIDEO_TAGS)
    if extra:
        found.append(Finding(path, "métadonnées", "métadonnée restante", ", ".join(extra)))
    signature = ENCODER_SIGNATURE_RE.search(file.read_bytes())
    if signature:
        found.append(Finding(path, "flux", "signature d'encodeur", signature.group(0).decode(errors="replace")))
    return found


def scan_image(path: str, file: Path, digest: str, blacklist) -> list[Finding]:
    def compute():
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "x2.png"
            upscale(file, big)
            return ocr(file) + "\n" + ocr(big)
    text = cached(f"img-{digest}", compute)
    found = scan_text(path, text, blacklist, label="OCR, ligne")
    found += scan_text(path, ocr_variant(text), blacklist, label="OCR corrigé, ligne")
    return found + image_metadata_findings(path, file)


def scan_video(path: str, file: Path, digest: str, blacklist, fps: str) -> list[Finding]:
    def compute():
        with tempfile.TemporaryDirectory() as tmp:
            vf = "scale=iw*2:ih*2:flags=lanczos" if fps == "all" else f"fps={fps},scale=iw*2:ih*2:flags=lanczos"
            subprocess.run(["ffmpeg", "-v", "error", "-i", str(file), "-vf", vf, "-vsync", "0",
                            f"{tmp}/f%06d.png"], check=True)
            parts = []
            for frame in sorted(Path(tmp).glob("f*.png")):
                parts.append(f"=== image {frame.stem[1:]}\n{ocr(frame)}")
            return "\n".join(parts)
    text = cached(f"vid-{fps}-{digest}", compute)
    found = []
    for block in text.split("=== image ")[1:]:
        number, _, body = block.partition("\n")
        label = f"image {int(number)} ({'toutes' if fps == 'all' else fps + '/s'}), ligne"
        found += scan_text(path, body, blacklist, label=label)
        found += scan_text(path, ocr_variant(body), blacklist, label=label + " (corrigé)")
    return found + video_metadata_findings(path, file)


# ---------------------------------------------------------------- dépôt

def git(*args) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def candidate_files() -> list[str]:
    return [f for f in git("ls-files", "-co", "--exclude-standard", "-z").split("\0") if f]


def staged_files() -> list[str]:
    return [f for f in git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0") if f]


def author_findings(staged: bool) -> list[Finding]:
    """Sur GitHub, l'e-mail de chaque commit est public : seule l'adresse noreply passe."""
    found = []
    if staged:
        ident = git("var", "GIT_AUTHOR_IDENT")
        email = ident[ident.find("<") + 1:ident.find(">")]
        if not NOREPLY_RE.search(email):
            found.append(Finding("git config", "user.email", "e-mail d'auteur public", email))
    log = subprocess.run(["git", "log", "--all", "--format=%ae%n%ce"], capture_output=True, text=True).stdout
    for email in sorted(set(filter(None, log.split("\n")))):
        if not NOREPLY_RE.search(email):
            found.append(Finding("historique", "auteur", "e-mail d'auteur public", email))
    return found


def history_text() -> str:
    """Messages et diffs de tous les commits, sans les lignes d'auteur (vérifiées à part)."""
    r = subprocess.run(["git", "log", "-p", "--all", "--no-color", "--format=commit %h%n%B"],
                       capture_output=True, text=True, errors="replace")
    return r.stdout


def scan_file(path: str, data: bytes, blacklist, fps: str) -> list[Finding]:
    ext = Path(path).suffix.lower()
    if ext in BINARY_SKIP_EXT:
        return [Finding(path, "fichier", "type non vérifiable", ext)]
    if ext in IMAGE_EXT or ext in VIDEO_EXT:
        for tool in ("tesseract", "ffmpeg", "ffprobe", "exiftool"):
            require(tool)
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / f"media{ext}"
            file.write_bytes(data)
            if ext in IMAGE_EXT:
                return scan_image(path, file, digest, blacklist)
            return scan_video(path, file, digest, blacklist, fps)
    if b"\0" in data[:8000]:
        return [Finding(path, "fichier", "binaire inconnu", "à convertir ou à retirer")]
    return scan_text(path, data.decode("utf-8", errors="replace"), blacklist)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true", help="vérifie aussi la version indexée")
    ap.add_argument("--generic-only", action="store_true", help="sans liste noire (CI)")
    ap.add_argument("--every-frame", action="store_true", help="OCR de chaque image des vidéos")
    ap.add_argument("--fps", default="5", help="images par seconde passées à l'OCR (défaut 5)")
    ap.add_argument("--history", action="store_true", help="vérifie aussi tout l'historique git")
    ap.add_argument("--show", action="store_true", help="affiche les valeurs en clair")
    ap.add_argument("paths", nargs="*", help="fichiers précis (par défaut : tout le dépôt)")
    args = ap.parse_args()
    fps = "all" if args.every_frame else args.fps

    blacklist = []
    if not args.generic_only:
        path = Path(os.environ.get("HOMELAB_DEMO_BLACKLIST", DEFAULT_BLACKLIST)).expanduser()
        if not path.is_file():
            print(f"Liste noire introuvable ({path}) : refus. Voir tools/build_blacklist.py.", file=sys.stderr)
            return 2
        blacklist = load_blacklist(path)

    os.chdir(git("rev-parse", "--show-toplevel").strip())
    targets = args.paths or candidate_files()
    findings = []
    for path in targets:
        if Path(path).is_file():
            findings += scan_file(path, Path(path).read_bytes(), blacklist, fps)
    if args.staged:
        for path in staged_files():
            data = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True).stdout
            findings += [Finding(f"{f.path} (indexé)", f.where, f.rule, f.value)
                         for f in scan_file(path, data, blacklist, fps)]

    if args.history:
        findings += scan_text("historique git", history_text(), blacklist)
    if not args.paths:
        findings += author_findings(args.staged)

    unique = {(f.path, f.where, f.rule, f.value): f for f in findings}.values()
    for f in sorted(unique, key=lambda f: (f.path, f.where)):
        value = f.value if args.show else mask(f.value)
        print(f"FUITE  {f.path}  [{f.where}]  {f.rule} : {value}")
    mode = "générique" if args.generic_only else f"liste noire de {len(blacklist)} entrées + générique"
    if unique:
        print(f"\n{len(unique)} correspondance(s) dans {len(targets)} fichier(s) ({mode}). Commit bloqué.")
        return 1
    print(f"OK : {len(targets)} fichier(s) vérifié(s), aucune correspondance ({mode}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
