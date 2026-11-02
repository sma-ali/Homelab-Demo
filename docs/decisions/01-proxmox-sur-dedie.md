# 01. Un serveur dédié sous Proxmox VE

## Contexte

En 2020, j'avais monté un premier labo (Proxmox, pfSense, fail2ban) sans rien documenter. Quelques
années plus tard, il n'en restait rien, ni la configuration ni le savoir-faire. Le nouvel
objectif : un environnement de développement virtualisé, sécurisé, et joignable de n'importe où
avec un simple portable et une connexion Internet.

## Options

- **Un VPS** : simple, mais une seule machine, et pas de quoi faire tourner un pare-feu et
  plusieurs VM isolées derrière lui.
- **Le cloud public** : facturé à l'usage. Pour un labo allumé en permanence, la facture grimpe
  vite et devient difficile à prévoir.
- **Un serveur à la maison** : pas de matériel disponible, une connexion résidentielle, le bruit
  et l'électricité. Gardé pour la phase 2 (un NAS).
- **Un serveur dédié avec un hyperviseur** : tout le matériel pour moi, un prix fixe, et la
  liberté de découper la machine comme je veux.

## Décision

Un serveur dédié chez OVH, pour une trentaine d'euros par mois, choisi sur quatre critères :

- un processeur récent et rapide, avec des SSD ;
- une **console de secours** (IPMI) incluse : sur un serveur distant, c'est le filet quand une
  règle de pare-feu vous enferme dehors ;
- un **espace de sauvegarde** inclus ;
- une seule IP publique suffit, puisque tout passe par le VPN.

Dessus, **Proxmox VE** dans sa dernière version majeure : de vraies VM (KVM) et des conteneurs
légers (LXC), une interface web, et les sauvegardes intégrées.

## Conséquences

- Tout repose sur une seule machine : une panne matérielle arrête tout. Les sauvegardes
  couvrent la perte de données, pas l'indisponibilité.
- La RAM devient la ressource à surveiller, VM par VM (voir [architecture](../architecture.md)).
- Avec une seule IP publique, l'hôte fait du NAT pour le pare-feu : il devient lui-même une
  surface à protéger, ce qui m'a rattrapé plus tard (voir [le scan externe](../retours/01-scan-externe-ipv6.md)).
