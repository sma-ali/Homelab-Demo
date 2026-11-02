# Architecture

## Trois réseaux

| Réseau | Qui y est | Rôle |
|---|---|---|
| Public | l'hôte seul | face à Internet, avec une seule adresse IPv4 et une adresse IPv6 |
| Transit | l'hôte et la VM pare-feu | relie les deux, et rien d'autre : un réseau de deux adresses |
| Interne | les VM | derrière le pare-feu, invisible depuis Internet |

Chaque réseau est un pont Linux sur l'hôte Proxmox. La VM pare-feu a deux cartes réseau, une
côté transit, une côté interne : tout ce qui entre ou sort du réseau interne passe par elle.

## Une seule IP publique, donc du NAT

Le serveur n'a qu'une adresse IPv4 publique, portée par l'hôte. Deux règles de NAT sur l'hôte
suffisent :

- **en sortie**, le trafic du pare-feu est masqué derrière l'adresse publique (masquerade) ;
- **en entrée**, seul le port UDP du VPN est redirigé vers la VM pare-feu (DNAT).

Tout le reste de ce qui arrive sur l'interface publique est rejeté par le pare-feu de l'hôte,
en IPv4 comme en IPv6 (voir [le scan externe](retours/01-scan-externe-ipv6.md)).

Pourquoi ne pas louer une IP supplémentaire pour le pare-feu ? Parce que l'accès passe par le
VPN : une deuxième adresse publique n'apporterait rien, et l'offre sans IP supplémentaire coûte
moins cher.

## Le trajet d'une connexion

1. Mon poste envoie ses paquets WireGuard vers l'adresse publique du serveur, sur le port du VPN.
2. L'hôte les redirige vers la VM pare-feu. La redirection intervient **avant** le filtrage de ce
   qui est destiné à l'hôte lui-même : la règle « tout rejeter » ne touche donc pas le VPN.
3. OPNsense déchiffre le tunnel, applique les règles propres à chaque appareil, puis route vers
   le réseau interne.
4. Pour administrer l'hôte, je passe par le tunnel puis par le réseau de transit : le panel
   Proxmox n'écoute jamais du côté public.

## Le piège de la route retour

Le tunnel montait, le réseau interne répondait, mais l'hôte restait muet depuis le VPN. Il
recevait bien des paquets venant des adresses du tunnel, mais ne savait pas par où répondre :
ces adresses n'existent que dans OPNsense. Il a fallu donner à l'hôte une route vers le réseau
du VPN via le pare-feu, et l'écrire dans la configuration réseau pour qu'elle survive au
redémarrage.

## Le partage des ressources

Sur ce serveur, la RAM est la ressource rare, pas le CPU :

| Qui | RAM |
|---|---|
| Hôte | ~2 Go |
| VM pare-feu | 4 Go |
| VM de dev | 4 Go |
| VM de production | 8 Go |
| **Libre** | **~14 Go** |

La VM de production a une priorité CPU deux fois plus basse que le reste. Ce n'est pas une
limite : tant que le serveur n'est pas saturé, elle prend tout ce qu'elle veut. Le réglage
n'arbitre que dans les moments de tension, et c'est alors le pare-feu, donc le VPN, qui passe
en premier.

## Les appareils

- **Le poste de travail** : le client WireGuard tourne dans WSL (Linux sous Windows), pas sous
  Windows. Le labo n'est ouvert qu'à l'environnement de développement, et le tunnel remonte
  seul au démarrage.
- **Les autres appareils** ont chacun leur propre pair, limité à une seule VM et à un seul
  service. Un appareil compromis n'atteindrait rien d'autre.
- **Les clés privées** sont générées sur l'appareil lui-même et ne le quittent jamais. En cas de
  perte, on supprime le pair côté serveur.
