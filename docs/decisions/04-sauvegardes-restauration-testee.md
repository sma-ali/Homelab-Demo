# 04. Sauvegardes : tout, chaque nuit, et une restauration testée

## Contexte

Toutes les VM vivent sur un seul serveur. Une erreur de manipulation, une mise à jour ratée ou
un disque qui lâche, et des semaines de configuration disparaissent. L'hébergeur fournit un
espace de sauvegarde, accessible en NFS depuis le serveur seulement.

## Options

- **Sauvegarder une liste de VM choisies** : précis, mais la VM créée trois mois plus tard finit
  toujours par être oubliée.
- **Tout sauvegarder par défaut** : plus volumineux, mais aucune VM ne passe entre les mailles.
- **Sauvegarder les fichiers à l'intérieur des VM** : plus fin, mais une restauration complète
  demande de tout réinstaller d'abord.

## Décision

Sauvegarde native de Proxmox (`vzdump`), **toutes les VM**, chaque nuit, en mode snapshot (sans
arrêter les VM), compressée en ZSTD. Rétention : 7 sauvegardes quotidiennes, 3 hebdomadaires,
2 mensuelles.

Les **disques de données régénérables** (rendus, caches de modèles) sont exclus : on sauvegarde
ce qui est coûteux à reconstruire, pas ce qui est volumineux.

### La restauration testée

Une sauvegarde jamais restaurée n'est qu'une hypothèse. J'ai restauré la VM de dev **à côté** de
l'originale :

1. restauration sous un nouvel identifiant, sans démarrage automatique ;
2. adresse MAC régénérée, pour ne pas avoir deux cartes réseau identiques ;
3. carte réseau **débranchée avant le démarrage** : l'adresse IP est écrite dans le système de
   la VM, et la copie aurait pris celle de l'originale ;
4. démarrage, connexion, vérification du système : intact ;
5. suppression de la copie et de ses disques.

La restauration a aussi expliqué la taille des archives : 76,5 % du disque de la VM n'avait
jamais été écrit, et `vzdump` ne copie pas le vide. Une sauvegarde complète de toutes les VM
prenait alors 94 secondes.

## Conséquences

- Toute nouvelle VM est couverte sans y penser.
- La configuration du pare-feu a en plus son propre export chiffré, indépendant des archives.
- L'espace de sauvegarde est limité : sa croissance doit être surveillée. Je l'ai appris à mes
  dépens (voir [deux semaines de sauvegardes ratées](../retours/02-sauvegarde-silencieuse.md)).
- Les archives sont dans le même datacenter que le serveur : elles couvrent la panne de disque,
  pas le sinistre du site. Une copie hors site est prévue.
