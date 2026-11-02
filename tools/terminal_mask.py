#!/usr/bin/env python3
"""Masque de terminal : le pendant du masque de navigateur, pour les plans enregistrés en texte.

Mêmes règles que tools/mask/mask.js (table des remplacements et liste noire, hors dépôt) :
chaque valeur sensible est remplacée AVANT d'atteindre l'écran, et si une valeur passe malgré
tout, l'affichage s'arrête sur un écran d'alarme. La prise est alors à refaire.

Sous-commandes :
    filter            masque un flux (stdin → stdout), au fil de l'eau ; utilisé par tools/scene.sh
    text TEXTE        affiche TEXTE masqué (pour taper une commande déjà masquée)
    cast ENTRÉE SORTIE
                      prépare un enregistrement asciinema pour l'export : coupe tout ce qui
                      précède le repère de début, masque à nouveau chaque événement, puis vérifie
                      le texte visible ; refuse d'écrire SORTIE s'il reste une valeur sensible.
"""

import argparse
import codecs
import json
import os
import re
import select
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_mask as bm  # noqa: E402
import check_leaks as cl  # noqa: E402

CONFIG = Path("~/.config/homelab_demo").expanduser()
START_MARK = "\x1b]2;debut-de-prise\x07"  # titre de fenêtre invisible, posé par tools/scene.sh
ALARM = ("\x1b[0m\x1b[2J\x1b[H\r\n  MASQUE : une valeur sensible allait s'afficher.\r\n"
         "  Coupe la prise (Ctrl+D) et recommence.\r\n")

DOC_V4 = ("192.0.2.", "198.51.100.", "203.0.113.")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
IPV4_DASHED = re.compile(r"(?<!\d)(?<!\d-)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?!\d|-\d)")
SSH_KEY = re.compile(r"\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)\s+AAAA[A-Za-z0-9+/=]{20,}")
IPV6 = re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{1,4}:|:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
EMAIL = re.compile(r"(?<![\w.+-])\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
WG_KEY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])")
FINGERPRINT = re.compile(r"\bSHA256:[A-Za-z0-9+/]{43}\b")
VERSION = re.compile(r"(?<![\w.])\d+\.\d+\.\d+(?:[-~]\d+)*(?:-pve|-amd64|-RELEASE(?:-p\d+)?)?(?![\w]|\.\d)")
FAKE_KEY = ("Exemp1eCleFactice" + "0" * 26)[:42] + "B="

SGR = re.compile(r"\x1b\[[0-9;:]*m")  # couleurs : retirées, le texte autour se recolle
OTHER_ESC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[@-_]")


def js_to_py_template(fake: str):
    """« $1 » des remplacements JavaScript, appliqué à un résultat de recherche Python."""
    return lambda m: re.sub(r"\$(\d)", lambda g: m.group(int(g.group(1))) or "", fake)


def js_hash(s: str) -> int:
    h = 0
    for c in s:
        h = (h * 31 + ord(c)) & 0xFFFFFFFF
    return h


def is_doc_v4(ip: str) -> bool:
    return ip.startswith(DOC_V4) or ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("255.")


def is_ipv6(s: str) -> bool:
    groups = [g for g in s.split(":") if g]
    if len(groups) < 3:
        return False
    return len(groups) <= 7 if "::" in s else len(groups) == 8


class Rules:
    def __init__(self, blacklist: Path, replacements: Path):
        self.blacklist = cl.load_blacklist(blacklist)
        literals, regexes, prefixes = bm.parse_replacements(replacements)
        literals.sort(key=lambda pair: -len(pair[0]))
        self.replacements = [(re.compile(bm.js_literal(real), re.I), js_to_py_template(fake))
                             for real, fake in literals]
        self.replacements += [(re.compile(src, re.I), js_to_py_template(fake)) for src, fake in regexes]
        self.prefixes = prefixes

    def fake_ipv4(self, ip: str) -> str:
        if is_doc_v4(ip):
            return ip
        for real, fake in self.prefixes:
            if ip == real:
                return fake
            if real.endswith(".") and ip.startswith(real):
                return fake + ip[len(real):]
        return f"{DOC_V4[js_hash(ip) % 3]}{200 + js_hash(ip) % 50}"

    def replace(self, text: str) -> str:
        """Même suite de remplacements que replaceText() dans tools/mask/mask.js."""
        if not text or len(text) < 2:
            return text
        for rx, by in self.replacements:
            text = rx.sub(by, text)
        text = SSH_KEY.sub(lambda m: f"{m.group(1)} AAAAcle-factice", text)
        text = MAC.sub(lambda m: m.group(0) if m.group(0).lower().replace("-", ":").startswith(cl.DOC_MAC_PREFIX)
                       else f"00:00:5e:00:53:{js_hash(m.group(0)) % 256:02x}", text)
        text = IPV4.sub(lambda m: self.fake_ipv4(m.group(0)), text)

        def dashed(m):
            octets = m.groups()
            if not all(int(o) <= 255 for o in octets):
                return m.group(0)
            return self.fake_ipv4(".".join(octets)).replace(".", "-")
        text = IPV4_DASHED.sub(dashed, text)

        def v6(m):
            ip = m.group(0)
            if not is_ipv6(ip) or re.match(r"^2001:0?db8:", ip, re.I) or ip in ("::1", "::"):
                return ip
            return f"2001:db8::{js_hash(ip) % 0xFFFF:x}"
        text = IPV6.sub(v6, text)
        text = EMAIL.sub(lambda m: m.group(0) if m.group(0).lower().endswith("@exemple.lab") else "admin@exemple.lab", text)
        text = UUID.sub("uuid-factice", text)
        text = WG_KEY.sub(FAKE_KEY, text)
        text = FINGERPRINT.sub("SHA256:empreinte-factice", text)
        return VERSION.sub("x.y.z", text)

    def leaks(self, visible_text: str) -> bool:
        return bool(cl.scan_text("terminal", visible_text, self.blacklist))


def visible(text: str) -> str:
    """Le texte tel qu'il s'affiche, à peu près : couleurs retirées, déplacements → retour à la ligne."""
    return OTHER_ESC.sub("\n", SGR.sub("", text)).replace("\r", "\n")


def safe_cut(text: str) -> int:
    """Position jusqu'où émettre sans couper un mot : une valeur n'est jamais à cheval."""
    for i in range(len(text) - 1, -1, -1):
        c = text[i]
        if c == "\x1b":
            return i
        if c.isspace():
            return i + 1
    return len(text) if len(text) > 4096 else 0


class StreamMasker:
    """Masque un flux arrivé par morceaux. feed() rend ce qu'on peut afficher sans risque."""

    def __init__(self, rules: Rules):
        self.rules = rules
        self.pending = ""
        self.tail = ""  # fin du texte visible déjà émis, pour les valeurs coupées en deux
        self.alarmed = False

    def _emit(self, chunk: str) -> str:
        if self.alarmed or not chunk:
            return ""
        cleaned = self.rules.replace(chunk)
        tail = (self.tail + visible(cleaned))[-2000:]
        if self.rules.leaks(tail):
            self.alarmed = True
            return ALARM
        self.tail = tail
        return cleaned

    def feed(self, text: str) -> str:
        self.pending += text
        cut = safe_cut(self.pending)
        chunk, self.pending = self.pending[:cut], self.pending[cut:]
        return self._emit(chunk)

    def flush(self) -> str:
        chunk, self.pending = self.pending, ""
        return self._emit(chunk)


def default_rules() -> Rules:
    return Rules(CONFIG / "liste-noire.txt", CONFIG / "remplacements.txt")


def run_filter(rules: Rules) -> int:
    masker = StreamMasker(rules)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    fd_in, out = sys.stdin.buffer.fileno(), sys.stdout.buffer
    while True:
        ready, _, _ = select.select([fd_in], [], [], 0.15)
        if ready:
            data = os.read(fd_in, 65536)
            if not data:
                out.write(masker.flush().encode())
                out.flush()
                break
            shown = masker.feed(decoder.decode(data))
        else:
            shown = masker.flush()  # rien de neuf depuis 150 ms : on affiche le mot en attente
        if shown:
            out.write(shown.encode())
            out.flush()
    return 1 if masker.alarmed else 0


def read_cast(path: Path):
    """En-tête et événements (temps absolu, type, données), asciicast v2 ou v3."""
    lines = path.read_text().splitlines()
    header = json.loads(lines[0])
    events, now = [], 0.0
    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        t, kind, data = json.loads(line)[:3]
        now = now + t if header.get("version") == 3 else t
        events.append((now, kind, data))
    return header, events


def prepare_cast(src: Path, dst: Path, rules: Rules) -> int:
    header, events = read_cast(src)
    outputs = [(t, d) for t, kind, d in events if kind == "o"]
    start = next((i for i, (_, d) in enumerate(outputs) if START_MARK in d), None)
    if start is None:
        print("Repère de début introuvable : l'enregistrement ne vient pas de tools/scene.sh.", file=sys.stderr)
        return 2
    t0 = outputs[start][0]
    first = outputs[start][1].split(START_MARK, 1)[1]
    kept = [(0.0, first)] + [(t - t0, d) for t, d in outputs[start + 1:]]

    # chaque événement garde son horodatage (la frappe reste caractère par caractère) ;
    # une valeur coupée entre deux événements échappe au remplacement, mais pas au contrôle
    # du texte visible complet, qui recolle tout
    cleaned = [(t, rules.replace(d)) for t, d in kept]
    full_visible = visible("".join(d for _, d in cleaned))
    if "MASQUE : une valeur sensible" in full_visible or rules.leaks(full_visible):
        print("Refus : une valeur sensible reste dans l'enregistrement. Refaire la prise.", file=sys.stderr)
        return 1

    term = header.get("term", {})
    width = header.get("width") or term.get("cols")
    height = header.get("height") or term.get("rows")
    with dst.open("w") as f:
        f.write(json.dumps({"version": 2, "width": width, "height": height}) + "\n")
        for t, d in cleaned:
            f.write(json.dumps([round(t, 6), "o", d], ensure_ascii=False) + "\n")
    print(f"Enregistrement prêt : {dst} ({len(cleaned)} événements, {cleaned[-1][0] if cleaned else 0:.1f} s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("filter")
    p_text = sub.add_parser("text")
    p_text.add_argument("text")
    p_cast = sub.add_parser("cast")
    p_cast.add_argument("src", type=Path)
    p_cast.add_argument("dst", type=Path)
    args = ap.parse_args()

    rules = default_rules()
    if args.cmd == "filter":
        return run_filter(rules)
    if args.cmd == "text":
        shown = rules.replace(args.text)
        if rules.leaks(shown):
            print("Refus : ce texte garde une valeur sensible une fois masqué.", file=sys.stderr)
            return 1
        print(shown)
        return 0
    return prepare_cast(args.src, args.dst, rules)


if __name__ == "__main__":
    sys.exit(main())
