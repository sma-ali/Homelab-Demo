# 02. OPNsense plutôt que pfSense

## Contexte

Le premier labo tournait sous pfSense, et le plan de départ le reprenait. Au moment de
l'installation, la version libre de pfSense accessible en téléchargement direct n'était plus à
jour, et la version courante demandait un compte chez l'éditeur.

## Options

- **pfSense** : connu, mais une version libre en retard, ou un compte à créer pour la dernière.
- **OPNsense** : issu de pfSense, entièrement open source, publié à un rythme régulier, et
  téléchargeable directement, sans compte.

## Décision

**OPNsense**, en machine virtuelle, avec deux cartes réseau : une côté transit vers l'hôte, une
côté réseau interne. Il fait office de pare-feu, de routeur pour les VM et de serveur WireGuard.
Image d'installation vérifiée par son empreinte SHA256 avant usage.

Ce qui a compté : une version à jour pour la sécurité, et la souveraineté (rien qui dépende d'un
compte chez un éditeur).

## Conséquences

- Son interface « WAN » est en adresse privée, derrière le NAT de l'hôte : il a fallu désactiver
  le blocage des réseaux privés qu'OPNsense applique par défaut sur le WAN.
- Placé derrière le NAT, il ne voit que le trafic du VPN. Les scans et tentatives venus
  d'Internet frappent l'hôte, pas lui, ce qui a pesé dans la [décision sur CrowdSec](05-crowdsec-differe.md).
- Sa configuration est exportée et chiffrée à part, après chaque changement important : on peut
  la réinjecter dans un OPNsense neuf sans restaurer toute la VM.
- La VM pare-feu démarre en premier au boot de l'hôte : sans elle, ni VPN ni réseau interne.
