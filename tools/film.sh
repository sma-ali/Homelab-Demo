#!/usr/bin/env bash
# Ouvre une fenêtre de tournage : Chromium avec un profil dédié, le masque chargé, sans onglets
# ni barre d'adresse. Le masque est reconstruit à chaque lancement, à partir de la liste noire
# du moment.
#
# Usage : tools/film.sh proxmox|opnsense
# Réglages privés dans ~/.config/homelab_demo/film.env : CHROME, PROXMOX_URL, OPNSENSE_URL.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$HOME/.config/homelab_demo"
# shellcheck source=/dev/null
source "$CONF/film.env"

case "${1:-}" in
  proxmox) URL="$PROXMOX_URL" ;;
  opnsense) URL="$OPNSENSE_URL" ;;
  *) echo "Usage : $0 proxmox|opnsense" >&2; exit 2 ;;
esac

python3 "$REPO/tools/build_mask.py" >/dev/null

# --disable-infobars et --test-type : pas de bandeau « Chrome for Testing » ni d'avertissement
# sur les options de lancement, qui apparaîtraient dans chaque prise.

exec "$CHROME" \
  --user-data-dir="$CONF/profil-tournage" \
  --disable-extensions-except="$CONF/masque" \
  --load-extension="$CONF/masque" \
  --app="$URL" \
  --window-size=1600,900 \
  --no-first-run --no-default-browser-check \
  --disable-notifications \
  --disable-infobars --test-type \
  --disable-features=Translate \
  --lang=fr
