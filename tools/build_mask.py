#!/usr/bin/env python3
"""Assemble le masque de tournage (extension Chrome) HORS du dépôt.

Lit la liste noire et la table des remplacements (toutes deux privées), écrit rules.js, puis
copie le code générique (tools/mask/) à côté. Le dossier produit se charge dans Chrome en
« extension non empaquetée ».

Table des remplacements, une règle par ligne :
    valeur réelle => valeur factice          (mot entier, sans tenir compte de la casse)
    re:EXPRESSION => valeur factice          (expression JavaScript, $1… permis)
    ipv4 PRÉFIXE. => PRÉFIXE FACTICE.        (garde le dernier octet : A.B.C.7 → 192.0.2.7)
    ipv4 ADRESSE => ADRESSE FACTICE

Usage :
    tools/build_mask.py [--blacklist …] [--replacements …] [--out …]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_leaks as cl  # noqa: E402

CONFIG = Path("~/.config/homelab_demo").expanduser()


def js_literal(value: str) -> str:
    """Expression JavaScript (sans drapeau u) qui trouve la valeur en mot entier."""
    body = r"\s+".join(re.escape(part) for part in value.split())
    return rf"(?<![\w]){body}(?![\w])"


def js_detector(entry: str) -> str | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    if entry.startswith("re:"):
        return entry[3:]
    if entry.startswith("port:"):
        return cl.compile_entry(entry)[1].pattern
    return js_literal(entry)


def parse_replacements(path: Path):
    literals, regexes, prefixes = [], [], []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=>" not in line:
            raise SystemExit(f"Remplacements, ligne {n} : « => » manquant.")
        real, fake = (part.strip() for part in line.split("=>", 1))
        if real.startswith("ipv4 "):
            prefixes.append([real[5:].strip(), fake])
        elif real.startswith("re:"):
            regexes.append([real[3:], fake])
        else:
            literals.append([real, fake])
    return literals, regexes, prefixes


def check_fakes(fakes: list[str], blacklist) -> list[str]:
    """Une valeur factice ne doit déclencher ni la liste noire ni les règles génériques."""
    bad = []
    for fake in fakes:
        text = re.sub(r"\$\d", "", fake)
        if cl.scan_text("remplacement", text, blacklist):
            bad.append(fake)
    return bad


def validate_in_node(rules_js: Path):
    script = (
        "globalThis.window=globalThis;"
        f"require({json.dumps(str(rules_js))});"
        "const R=globalThis.__MASK_RULES__;let bad=0;"
        "for(const [s,f] of [...R.replacements,...R.detectors])"
        "{try{new RegExp(s,f)}catch(e){bad++;console.error('invalide : '+e.message.slice(0,80))}}"
        "process.exit(bad?1:0)"
    )
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True)
    if r.returncode:
        raise SystemExit("Expression refusée par JavaScript :\n" + r.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--blacklist", type=Path, default=CONFIG / "liste-noire.txt")
    ap.add_argument("--replacements", type=Path, default=CONFIG / "remplacements.txt")
    ap.add_argument("--out", type=Path, default=CONFIG / "masque")
    args = ap.parse_args()

    out = args.out.expanduser()
    if HERE.parent in out.resolve().parents or out.resolve() == HERE.parent:
        print("Refus : le masque contient les vraies valeurs, jamais dans le dépôt.", file=sys.stderr)
        return 2

    blacklist_path = args.blacklist.expanduser()
    blacklist = cl.load_blacklist(blacklist_path)
    literals, regexes, prefixes = parse_replacements(args.replacements.expanduser())

    bad = check_fakes([f for _, f in literals + regexes] + [f for _, f in prefixes], blacklist)
    if bad:
        print(f"Refus : {len(bad)} valeur(s) factice(s) tombent sous la liste noire :", file=sys.stderr)
        for fake in bad:
            print(f"  {fake}", file=sys.stderr)
        return 1

    # les plus longues d'abord : « nom.domaine » avant « nom »
    literals.sort(key=lambda pair: -len(pair[0]))
    replacements = [[js_literal(real), "i", fake] for real, fake in literals]
    replacements += [[source, "i", fake] for source, fake in regexes]
    detectors = []
    for line in blacklist_path.read_text().splitlines():
        source = js_detector(line)
        if source:
            detectors.append([source, "i"])

    rules = {"replacements": replacements, "detectors": detectors, "ipv4Prefixes": prefixes}

    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    rules_js = out / "rules.js"
    fd = os.open(rules_js, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("// Généré par tools/build_mask.py. Contient les vraies valeurs : ne jamais partager.\n")
        f.write(f"globalThis.__MASK_RULES__ = {json.dumps(rules, ensure_ascii=False, indent=1)};\n")
    for name in ("manifest.json", "mask.js"):
        shutil.copy(HERE / "mask" / name, out / name)
    validate_in_node(rules_js)

    # valeurs de la liste noire sans remplacement : si elles s'affichent, l'écran noir tombe
    replaced = [re.compile(source, re.I) for source, _, _ in replacements]
    orphans = [line for line in blacklist_path.read_text().splitlines()
               if line.strip() and not line.startswith(("#", "re:", "port:"))
               and not any(rx.search(line) for rx in replaced)]
    print(f"Masque écrit dans {out}")
    print(f"  {len(replacements)} remplacements, {len(prefixes)} préfixes IPv4, {len(detectors)} détecteurs")
    print(f"  {len(orphans)} valeur(s) de la liste noire sans remplacement : écran noir si elles s'affichent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
