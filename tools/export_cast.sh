#!/usr/bin/env bash
# Exporte un enregistrement de terminal (asciinema) en GIF publiable : coupe la préparation,
# masque et vérifie le texte, rend l'animation, retire les métadonnées, puis contrôle chaque
# image par OCR. Le GIF n'est gardé que si tout passe.
#
# Usage : tools/export_cast.sh rushes/SCÈNE.cast media/SORTIE.gif [ATTENTE_MAX] [VITESSE]
#   ATTENTE_MAX : durée maximale d'une pause, en secondes (défaut 1.5) ; VITESSE : défaut 1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IN="$1"; OUT="$2"; IDLE="${3:-1.5}"; SPEED="${4:-1}"
command -v agg >/dev/null || { echo "agg manquant (voir travail/plans-a-filmer.md)." >&2; exit 2; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

python3 "$REPO/tools/terminal_mask.py" cast "$IN" "$TMP/propre.cast"
agg --cols 100 --rows 28 --font-size 22 --theme monokai --idle-time-limit "$IDLE" --speed "$SPEED" \
  --last-frame-duration 3 "$TMP/propre.cast" "$OUT"
exiftool -q -overwrite_original -all= "$OUT"

echo "Contrôle de chaque image de $OUT…"
if ! python3 "$REPO/tools/check_leaks.py" --every-frame "$OUT"; then
  rm -f "$OUT"
  echo "Extrait supprimé : le contrôle a trouvé quelque chose. Refaire la prise." >&2
  exit 1
fi
echo "Extrait prêt : $OUT ($(du -h "$OUT" | cut -f1))"
