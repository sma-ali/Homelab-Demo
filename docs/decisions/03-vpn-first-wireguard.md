# 03. VPN-first, avec WireGuard

## Contexte

Je veux administrer le labo et travailler sur les VM depuis n'importe où. La façon la plus simple
serait d'exposer le panel Proxmox et le SSH sur Internet. C'est aussi la plus exposée : chaque
service ouvert est une surface d'attaque, scannée en permanence.

## Options

- **Exposer le panel et le SSH**, protégés par mot de passe fort, double authentification et
  bannissement des IP fautives : beaucoup de couches pour défendre une porte qu'on pourrait
  simplement fermer.
- **Tailscale** : très confortable, mais la coordination du réseau dépend d'un service tiers.
- **Headscale** : la même chose, auto-hébergée. Plus de pièces à maintenir ; gardé pour la phase 2.
- **WireGuard sur le pare-feu** : un seul port UDP, un protocole court et audité, et tout reste
  chez moi.

## Décision

**VPN-first avec WireGuard**, servi par OPNsense. Rien d'administrable n'écoute du côté public :
le panel, l'interface du pare-feu, le SSH et les VM ne sont joignables qu'à travers le tunnel.
J'ai fermé l'accès public au panel **après** avoir vérifié que le VPN fonctionnait, jamais avant.

## Conséquences

- Un seul port ouvert, et WireGuard ne répond à aucun paquet qui n'est pas signé par une clé
  connue : vu d'Internet, ce port paraît fermé lui aussi.
- Chaque appareil a son propre pair, limité au strict nécessaire : le poste de travail atteint
  le labo, les autres appareils une seule VM et un seul service.
- Si le VPN tombe, il reste la console de secours de l'hébergeur pour reprendre la main.
- Il a fallu comprendre le routage de bout en bout : sans route retour, l'hôte ne pouvait pas
  répondre aux machines du tunnel (voir [architecture](../architecture.md#le-piège-de-la-route-retour)).
- Le client WireGuard tourne dans WSL plutôt que sous Windows : le labo n'est ouvert qu'à
  l'environnement de développement, pas à tout le système.
