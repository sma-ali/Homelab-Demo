#!/usr/bin/env bash
# Tournage dans Chrome sous Windows : assemble le masque dans un dossier Windows, puis lance
# les relais qui rendent les panels joignables à https://localhost:PORT depuis Windows.
#
# Usage (sous WSL) : tools/film_windows.sh      puis Ctrl+C pour arrêter les relais.
# Réglages privés dans ~/.config/homelab_demo/film.env :
#   MASK_WINDOWS_DIR, PROXMOX_TARGET (hôte:port), OPNSENSE_TARGET (hôte:port)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$HOME/.config/homelab_demo/film.env"

python3 "$REPO/tools/build_mask.py" --out "$MASK_WINDOWS_DIR" | head -1
echo "Dans Chrome : chrome://extensions, mode développeur, « Charger l'extension non empaquetée »,"
echo "dossier ci-dessus (une seule fois). Après chaque mise à jour du masque : bouton ⟳ de l'extension."
echo
exec python3 "$REPO/tools/relay.py" "18006:$PROXMOX_TARGET" "18443:$OPNSENSE_TARGET"
