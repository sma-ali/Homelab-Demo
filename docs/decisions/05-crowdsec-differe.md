# 05. CrowdSec : étudié, puis différé

## Contexte

Le plan de départ prévoyait CrowdSec (ou fail2ban) pour repérer et bannir les adresses qui
tentent de forcer l'entrée. Avant de l'installer, je me suis demandé ce qu'il verrait vraiment
sur ce serveur.

## Qui voit les attaques ?

**L'hôte, pas le pare-feu.** Avec une seule IP publique, c'est l'hôte qui reçoit tout le trafic
d'Internet. OPNsense, derrière le NAT, ne reçoit que le port du VPN. Installer CrowdSec sur
OPNsense ne servirait donc à rien ici : s'il doit exister,
c'est sur l'hôte.

## Qu'y aurait-il à bannir ?

- Le SSH n'accepte que des clés : il n'y a pas de mot de passe à deviner.
- Le panel et le SSH ne sont joignables que par le VPN.
- Depuis le [scan externe](../retours/01-scan-externe-ipv6.md), l'hôte rejette tout ce qui arrive
  par l'interface publique, en IPv4 comme en IPv6.
- WireGuard ne répond à aucun paquet non signé par une clé connue.

Il ne reste aucun service public sur lequel une tentative pourrait seulement être journalisée.

## Décision

**Différé.** Ici, CrowdSec ajouterait un service à maintenir pour surveiller une porte qui
n'existe plus. Il reste une défense en profondeur possible, pas un manque.

## Ce qui me ferait changer d'avis

Exposer un service au public, un site web par exemple. CrowdSec irait alors sur l'hôte, avec
les collections adaptées au service exposé, et la décision serait documentée ici.
