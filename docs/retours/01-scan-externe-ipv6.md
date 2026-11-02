# J'ai scanné mon propre serveur et trouvé une porte ouverte en IPv6

*Novembre 2026.*

## L'hypothèse

Depuis la mise en place du VPN, le labo était censé n'exposer qu'une chose à Internet : le port
de WireGuard. Le panel Proxmox avait été fermé au public par une règle de pare-feu sur l'hôte.
Je ne l'avais jamais vérifié de l'extérieur.

## La vérification

- Un scan `nmap` des 65 535 ports TCP, lancé depuis une connexion 4G, donc hors de toute liste
  blanche.
- Sur l'hôte, `ss -tulnp` pour lister tout ce qui écoute, et sur quelle interface.
- Un test de connexion direct en IPv6.

## Ce que j'ai trouvé

- **En IPv4** : le panel était bien fermé, mais plusieurs services système écoutaient sur toutes
  les interfaces, publique comprise : SSH, des services liés à NFS, un proxy de console, un
  serveur de messagerie local.
- **En IPv6** : **aucune règle du tout**. L'hôte porte une adresse IPv6 publique, et le panel
  comme le SSH y répondaient. La règle posée des mois plus tôt ne protégeait que l'IPv4 : le
  « VPN-first » était faux de l'autre côté.

> La leçon : une règle `iptables` ne couvre jamais l'IPv6. Chaque règle IPv4 a besoin de sa
> jumelle `ip6tables`, sinon la porte reste ouverte.

## La correction

Plutôt que de fermer les services un par un, une politique simple sur l'interface publique de
l'hôte : tout rejeter, sauf ce dont on a besoin.

```bash
# IPv4 (valeurs remplacées par des noms génériques)
iptables  -A INPUT -i <interface-publique> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # réponses à nos propres connexions
iptables  -A INPUT -i <interface-publique> -p icmp -j ACCEPT                                     # ping, utilisé par la supervision de l'hébergeur
iptables  -A INPUT -i <interface-publique> -s <serveur-de-sauvegarde> -j ACCEPT                 # l'espace de sauvegarde
iptables  -A INPUT -i <interface-publique> -j DROP                                               # tout le reste

# IPv6
ip6tables -A INPUT -i <interface-publique> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -i <interface-publique> -p ipv6-icmp -j ACCEPT                                # sans ICMPv6, l'IPv6 cesse de fonctionner
ip6tables -A INPUT -i <interface-publique> -j DROP
```

Les règles sont rendues persistantes avec `netfilter-persistent`. Le VPN n'est pas touché : sa
redirection vers le pare-feu intervient avant ce filtrage. Le SSH public, devenu inutile, a été
fermé : tout passe par le VPN, avec la console de secours de l'hébergeur en dernier recours.

## Modifier un pare-feu à distance sans s'enfermer dehors

Sur un serveur distant, une règle fausse coupe la branche sur laquelle on est assis. J'ai donc
armé un **retour automatique** avant de toucher à quoi que ce soit :

```bash
# 1. sauvegarder l'état actuel et programmer sa restauration dans 10 minutes
iptables-save > /root/pare-feu-avant.v4 && ip6tables-save > /root/pare-feu-avant.v6 && \
  systemd-run --on-active=10min --unit=retour-pare-feu sh -c \
  'iptables-restore < /root/pare-feu-avant.v4; ip6tables-restore < /root/pare-feu-avant.v6'

# 2. appliquer les règles
# 3. tester : panel par le VPN, espace de sauvegarde monté, scan depuis l'extérieur

# 4. si tout va bien : annuler le retour et rendre les règles persistantes
systemctl stop retour-pare-feu.timer && netfilter-persistent save
```

Si l'accès se perd à l'étape 3, il suffit d'attendre : le serveur revient seul à l'état d'avant.

## Le faux positif

Le second scan, après correction, montrait tout filtré, sauf quelques ports web et de streaming
qui paraissaient ouverts. Même résultat en scannant `scanme.nmap.org` depuis la même 4G : c'était
le proxy transparent de l'opérateur mobile, pas mon serveur. Un résultat de scan dépend aussi du
réseau d'où on le lance.

## Ce que j'en retiens

- Une protection non vérifiée de l'extérieur n'est qu'une supposition.
- L'IPv6 est activée par défaut sur beaucoup de systèmes, et elle a ses propres règles.
- « Tout rejeter sauf » vaut mieux que « fermer service par service » : le prochain service
  installé sera protégé d'office.
