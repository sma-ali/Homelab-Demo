#!/usr/bin/env bash
# Exporte un rush en extrait publiable : muet, sans métadonnées, sans signature d'encodeur,
# puis le passe au contrôle image par image. L'extrait n'est gardé que si le contrôle passe.
#
# Usage : tools/export_clip.sh RUSH SORTIE.mp4|SORTIE.gif [DÉBUT] [FIN] [VITESSE]
#   GIF_WIDTH=1920 devant la commande : GIF en pleine largeur (défaut 1280).
#   DÉBUT, FIN : horodatages ffmpeg (ex. 00:00:03.5) ; VITESSE : 2 = deux fois plus vite.
# Exemple : tools/export_clip.sh rushes/plan1.mkv media/tableau-de-bord.mp4 00:00:02 00:00:16
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IN="$1"; OUT="$2"; START="${3:-0}"; END="${4:-}"; SPEED="${5:-1}"
TRIM=(-ss "$START"); [ -n "$END" ] && TRIM+=(-to "$END")
VF="setpts=PTS/$SPEED,scale='min(1920,iw)':-2:flags=lanczos"
mkdir -p "$(dirname "$OUT")"

case "$OUT" in
  *.mp4)
    ffmpeg -v error -y "${TRIM[@]}" -i "$IN" -an -vf "$VF,fps=30" \
      -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -movflags +faststart \
      -map_metadata -1 -fflags +bitexact -flags:v +bitexact -metadata:s:v:0 encoder= \
      -bsf:v filter_units=remove_types=6 "$OUT" ;;
  *.gif)
    ffmpeg -v error -y "${TRIM[@]}" -i "$IN" -an \
      -vf "setpts=PTS/$SPEED,scale='min(${GIF_WIDTH:-1280},iw)':-2:flags=lanczos,fps=12,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
      -map_metadata -1 -fflags +bitexact "$OUT"
    exiftool -q -overwrite_original -all= "$OUT" ;;
  *) echo "Sortie en .mp4 ou .gif seulement." >&2; exit 2 ;;
esac

echo "Contrôle de chaque image de $OUT…"
if ! python3 "$REPO/tools/check_leaks.py" --every-frame "$OUT"; then
  rm -f "$OUT"
  echo "Extrait supprimé : le contrôle a trouvé quelque chose. Refaire la prise." >&2
  exit 1
fi
echo "Extrait prêt : $OUT ($(du -h "$OUT" | cut -f1))"
