#!/usr/bin/env bash
# Scènes de terminal à enregistrer avec asciinema. Toute la sortie passe par le masque de
# terminal (tools/terminal_mask.py) : les vraies valeurs n'atteignent jamais l'écran.
#
# Usage (sous WSL) : asciinema rec -c "tools/scene.sh SCÈNE" rushes/SCÈNE.cast
#   vpn    sans VPN, le panel ne répond pas ; tunnel remonté, il répond
#   scan   scan externe de tous les ports TCP (depuis une connexion 4G)
#   htop   la VM de production au travail
# Réglages privés dans ~/.config/homelab_demo/film.env : PROXMOX_TARGET (hôte:port),
#   SCAN_TARGET (adresse publique), WG_IFACE (interface WireGuard), PROD_SSH (alias SSH).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
MASK="$REPO/tools/terminal_mask.py"
# shellcheck source=/dev/null
source "$HOME/.config/homelab_demo/film.env"
SCENE="${1:-}"

die() { echo "$*" >&2; exit 2; }

# ---------------------------------------------------------------- préparation (coupée au montage)
case "$SCENE" in
  vpn)
    [ -n "${PROXMOX_TARGET:-}" ] && [ -n "${WG_IFACE:-}" ] || die "PROXMOX_TARGET et WG_IFACE manquent dans film.env."
    echo "Mot de passe sudo (pour couper et remonter le tunnel), avant le début de la prise :"
    sudo -v || die "sudo refusé."
    trap 'sudo -n wg-quick up "$WG_IFACE" >/dev/null 2>&1 || true' EXIT ;;
  scan)
    [ -n "${SCAN_TARGET:-}" ] || die "SCAN_TARGET manque dans film.env."
    if ip route get "$SCAN_TARGET" 2>/dev/null | grep -q "dev wg"; then
      die "Le scan passerait par le tunnel : il doit partir d'Internet."
    fi ;;
  htop)
    ssh -o BatchMode=yes "${PROD_SSH:?PROD_SSH manque dans film.env}" true 2>/dev/null \
      || die "Connexion SSH impossible sans saisie : lance « ssh-add », puis recommence." ;;
  *) die "Scène inconnue. Choix : vpn, scan, htop." ;;
esac
stty cols 100 rows 28 2>/dev/null

# À partir d'ici, tout ce qui s'affiche passe par le masque.
exec > >(python3 "$MASK" filter) 2>&1
FILTER_PID=$!
printf '\033]2;debut-de-prise\007\033[H\033[2J' > /dev/tty

type_cmd() {
  # tape la commande déjà masquée (et vérifiée), caractère par caractère, directement à
  # l'écran, puis l'exécute pour de vrai : sa sortie, elle, passe par le masque
  local shown
  shown="$(python3 "$MASK" text "$1")" || exit 1
  printf '\033[1;32m$\033[0m ' > /dev/tty
  for ((i = 0; i < ${#shown}; i++)); do printf '%s' "${shown:i:1}" > /dev/tty; sleep 0.03; done
  sleep 0.4; printf '\r\n' > /dev/tty
  bash -c "$1"
  sleep 1.2
}
comment() { printf '\033[2m# %s\033[0m\r\n' "$1" > /dev/tty; sleep 1; }

CURL="curl -k -sS -o /dev/null -w 'HTTP %{http_code}\n' --connect-timeout 5 https://${PROXMOX_TARGET:-}/"

case "$SCENE" in
  vpn)
    comment "Sans le VPN, le panel d'administration est injoignable"
    type_cmd "sudo -n wg-quick down $WG_IFACE"
    type_cmd "$CURL"
    comment "Tunnel WireGuard remonté : le panel répond"
    type_cmd "sudo -n wg-quick up $WG_IFACE"
    type_cmd "$CURL" ;;
  scan)
    comment "Depuis une connexion 4G, hors de toute liste blanche : tous les ports TCP"
    type_cmd "nmap -Pn -n -p- --min-rate 1000 --stats-every 15s $SCAN_TARGET" ;;
  htop)
    type_cmd "ssh -t $PROD_SSH htop" ;;
esac

sleep 1.5
exec >&- 2>&-
wait "$FILTER_PID" 2>/dev/null
