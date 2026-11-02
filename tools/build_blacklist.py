#!/usr/bin/env python3
"""Génère la liste noire des valeurs sensibles, HORS du dépôt.

Extrait des sources privées (dépôts git, historique compris, et fichiers isolés) les adresses
IP, plages, ports, domaines, adresses MAC, UUID, clés et empreintes. Les ajouts manuels, placés
sous le marqueur « manuel », sont conservés à chaque régénération.

Usage :
    tools/build_blacklist.py --out ~/.config/homelab_demo/liste-noire.txt SOURCE [SOURCE ...]

Une SOURCE est un dépôt git (fichiers suivis + tout l'historique) ou un fichier.
Le script n'affiche jamais les valeurs trouvées, seulement leur nombre par catégorie.
"""

import argparse
import datetime
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

MANUAL_MARKER = "# === manuel (conservé à chaque régénération) ==="
AUTO_MARKER = "# === auto (régénéré, ne pas modifier à la main) ==="

HEADER = """# Liste noire de homelab_demo. Fichier privé, jamais dans le dépôt (droits 600).
# Syntaxe, une entrée par ligne :
#   valeur       recherchée telle quelle, sans tenir compte de la casse, en mot entier
#   port:N       le nombre N dans un contexte de port (:N, N/udp, port N…), ou partout si N >= 1000
#   re:REGEX     expression régulière Python, insensible à la casse
#   # …          commentaire
"""

# Sites publics cités comme références : ce ne sont pas des valeurs de l'infrastructure.
PUBLIC_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "gitlab.com", "blog.zwindler.fr", "netsplit.uk",
    "scanme.nmap.org", "nmap.org", "wireguard.com", "www.wireguard.com", "proxmox.com",
    "www.proxmox.com", "pve.proxmox.com", "forum.proxmox.com", "enterprise.proxmox.com",
    "download.proxmox.com", "opnsense.org", "docs.opnsense.org", "pkg.opnsense.org",
    "www.opnsense.org", "pfsense.org", "www.pfsense.org", "netgate.com", "www.netgate.com",
    "ubuntu.com", "www.ubuntu.com", "releases.ubuntu.com", "debian.org", "www.debian.org",
    "deb.debian.org", "security.debian.org", "letsencrypt.org", "crowdsec.net",
    "www.crowdsec.net", "app.crowdsec.net", "docs.crowdsec.net", "ovh.com", "www.ovh.com",
    "ovhcloud.com", "www.ovhcloud.com", "help.ovhcloud.com", "eco.ovhcloud.com",
    "play.google.com", "google.com", "www.google.com", "1password.com", "nodejs.org",
    "playwright.dev", "huggingface.co", "pypi.org", "astral.sh", "npmjs.com", "ffmpeg.org",
    "example.com", "example.org", "example.net", "exemple.lab", "learn.microsoft.com",
    "docs.github.com", "cli.github.com", "wikipedia.org", "fr.wikipedia.org",
    "en.wikipedia.org", "ntfy.sh", "docs.ntfy.sh", "localhost", "www.w3.org", "w3.org",
}

# Domaines de premier niveau retenus : le reste (nom.md, os.path, net.ipv4…) n'est pas un domaine.
KNOWN_TLDS = {
    "com", "net", "org", "fr", "eu", "io", "dev", "app", "arpa", "lan", "local", "internal",
    "lab", "uk", "de", "be", "ch", "co", "me", "info", "biz", "tv", "xyz",
    "cloud", "tech", "ovh", "site", "online", "pro", "ai",
}

IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?![\w.]*\d)")
IPV6_RE = re.compile(r"(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?:/(\d{1,3}))?(?![\w:])")
DOMAIN_RE = re.compile(r"(?<![\w.@-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]{1,23})(?![\w-])")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
UUID_RE = re.compile(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b")
FINGERPRINT_RE = re.compile(r"\b(SHA256:[A-Za-z0-9+/]{43})")
SSH_KEY_RE = re.compile(r"\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+) (AAAA[A-Za-z0-9+/=]{20,})(?: (\S+))?")
WG_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)(?![A-Za-z0-9+/=])")
PORT_RES = [
    re.compile(r"(?<![\w.]):(\d{2,5})\b"),
    re.compile(r"\b(\d{2,5})/(?:udp|tcp)\b", re.I),
    re.compile(r"\bports?\s+`?(\d{2,5})\b", re.I),
    re.compile(r"\b(?:--dport|--sport|dport|sport|ListenPort|Port)\s*=?\s*(\d{2,5})\b", re.I),
]
USER_HOST_RE = re.compile(r"(?<![\w.+-])([a-z_][a-z0-9_.-]{0,31})@([A-Za-z0-9][\w.-]*)")
SSH_HOST_RE = re.compile(r"^\s*(?:Host|HostName|User)\s+(.+)$", re.M)

DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def read_source(path: Path) -> str:
    """Texte d'un fichier, ou d'un dépôt git entier : fichiers suivis et tout l'historique."""
    if path.is_dir() and (path / ".git").exists():
        files = subprocess.run(["git", "-C", str(path), "ls-files", "-co", "--exclude-standard"],
                               capture_output=True, text=True, check=True).stdout.split("\n")
        chunks = []
        for name in filter(None, files):
            f = path / name
            if f.is_file():
                chunks.append(f.read_text(errors="replace"))
        history = subprocess.run(["git", "-C", str(path), "log", "-p", "--all", "--no-color"],
                                 capture_output=True, text=True, errors="replace", check=True).stdout
        chunks.append(history)
        return "\n".join(chunks)
    if path.is_dir():
        return "\n".join(f.read_text(errors="replace") for f in sorted(path.rglob("*")) if f.is_file())
    return path.read_text(errors="replace")


def is_doc(addr) -> bool:
    return any(addr.version == n.version and addr in n for n in DOC_NETS)


def extract(text: str) -> dict:
    found = {k: set() for k in ("ipv4", "ipv6", "domains", "ports", "mac", "uuid", "keys", "names")}

    for m in IPV4_RE.finditer(text):
        ip, prefix = m.group(1), m.group(2)
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_unspecified or ip.startswith("255.") or is_doc(addr):
            continue
        found["ipv4"].add(ip)
        found["ipv4"].add(ip.replace(".", "-"))  # forme des noms inverses (ip-a-b-c)
        if not addr.is_private:
            found["ipv4"].add(".".join(reversed(ip.split("."))))  # forme in-addr.arpa
        if prefix and 16 <= int(prefix) < 32:  # une plage plus large bannirait des nombres ordinaires
            net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            found["ipv4"].add(str(net))
            octets = str(net.network_address).split(".")
            keep = max(1, min(3, int(prefix) // 8))
            found["ipv4"].add("re:(?<![\\d.])" + re.escape(".".join(octets[:keep]) + "."))
        if not addr.is_private:
            # le voisinage d'une IP publique suffit à la situer
            found["ipv4"].add("re:(?<![\\d.])" + re.escape(".".join(ip.split(".")[:3]) + "."))
            found["ipv4"].add("-".join(ip.split(".")[:3]))

    for m in IPV6_RE.finditer(text):
        raw = m.group(1)
        if raw.count(":") < 2 or not re.search(r"[0-9a-fA-F]", raw):
            continue
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_unspecified or is_doc(addr):
            continue
        found["ipv6"].add(addr.compressed)
        found["ipv6"].add(addr.exploded)
        if addr.is_global:
            groups = addr.exploded.split(":")[:4]
            found["ipv6"].add("re:" + ":".join(f"0*{g.lstrip('0') or '0'}" for g in groups) + r"(?![0-9a-f])")

    for m in DOMAIN_RE.finditer(text):
        d = m.group(1).lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld not in KNOWN_TLDS or d in PUBLIC_DOMAINS:
            continue  # objet.méthode du code, nom de fichier, clé sysctl… : pas un domaine
        if any(d.endswith("." + p) for p in PUBLIC_DOMAINS if p.count(".") >= 1 and p not in
               {"google.com", "github.com", "ovh.com", "ovhcloud.com", "wikipedia.org"}):
            continue
        found["domains"].add(d)
        first = d.split(".")[0]
        if re.search(r"\d", first) and len(first) >= 5:
            found["domains"].add(first)  # nom d'hôte seul (ex. un nom de serveur numéroté)

    for rx in PORT_RES:
        for m in rx.finditer(text):
            n = int(m.group(1))
            if 1024 <= n <= 65535:  # sous 1024, ports standard (22, 80…) : ils ne révèlent rien
                found["ports"].add(f"port:{n}")

    for m in MAC_RE.finditer(text):
        found["mac"].add(m.group(1).lower())
        found["mac"].add(m.group(1).lower().replace("-", ":"))
    for m in UUID_RE.finditer(text):
        found["uuid"].add(m.group(1).lower())
    for m in FINGERPRINT_RE.finditer(text):
        found["keys"].add(m.group(1))
    for m in SSH_KEY_RE.finditer(text):
        found["keys"].add(m.group(2)[24:64])  # le début est commun à toutes les clés d'un type : on garde le milieu
        if m.group(3):
            found["names"].add(m.group(3))  # commentaire de la clé (souvent nom@machine)
    for m in WG_KEY_RE.finditer(text):
        found["keys"].add(m.group(1))
    for m in USER_HOST_RE.finditer(text):
        user, host = m.group(1), m.group(2).rstrip(".")
        if "." in host and host.lower() in PUBLIC_DOMAINS:
            continue
        found["names"].add(f"{user}@{host}")
    for m in SSH_HOST_RE.finditer(text):
        keyword = m.group(0).split()[0]
        for value in m.group(1).split():
            if value in {"*", "yes", "no"} or value.lower() in PUBLIC_DOMAINS:
                continue
            if keyword == "User":
                # un nom d'utilisateur peut être un prénom : banni seulement en contexte
                found["names"].add(f"re:\\b{re.escape(value)}@")
                found["names"].add(f"re:/home/{re.escape(value)}\\b")
                found["names"].add(f"re:\\b(?:User|-l|ssh)\\s+{re.escape(value)}\\b")
            else:
                found["names"].add(value)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("sources", nargs="+", type=Path)
    args = ap.parse_args()

    out = args.out.expanduser()
    repo_root = Path(__file__).resolve().parent.parent
    if repo_root in out.resolve().parents:
        print("Refus : la liste noire ne doit jamais être écrite dans le dépôt.", file=sys.stderr)
        return 2

    found = {}
    for src in args.sources:
        src = src.expanduser()
        if not src.exists():
            print(f"Source absente, ignorée : {src}", file=sys.stderr)
            continue
        for k, v in extract(read_source(src)).items():
            found.setdefault(k, set()).update(v)

    manual = ""
    if out.exists():
        old = out.read_text()
        if MANUAL_MARKER in old:
            manual = old.split(MANUAL_MARKER, 1)[1].lstrip("\n")

    lines = [HEADER, f"# Générée le {datetime.date.today().isoformat()} depuis {len(args.sources)} source(s).", AUTO_MARKER]
    for category in ("ipv4", "ipv6", "domains", "ports", "mac", "uuid", "keys", "names"):
        values = sorted(found.get(category, ()))
        lines.append(f"# --- {category} ({len(values)})")
        lines.extend(values)
    lines.append("")
    lines.append(MANUAL_MARKER)
    text = "\n".join(lines) + "\n" + manual

    out.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(out.parent, 0o700)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(out, 0o600)

    for category in ("ipv4", "ipv6", "domains", "ports", "mac", "uuid", "keys", "names"):
        print(f"{category:8} {len(found.get(category, ())):4}")
    print(f"Écrit dans {out} (droits 600). Valeurs non affichées.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
