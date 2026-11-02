# Deux semaines de sauvegardes ratées, sans alerte

*Octobre 2026, découvert en novembre.*

## Le constat

En relisant le journal des tâches Proxmox, j'ai vu que la sauvegarde de la VM de production
échouait chaque nuit depuis environ deux semaines, avec la même erreur : `vma_queue_write: write
error - Broken pipe`. Les autres VM, elles, étaient sauvegardées normalement. Personne n'avait
été prévenu.

## La cause

L'espace de sauvegarde était plein, à 96 %.

- L'archive de la VM de production était passée d'environ 5 à 13 Go. Son disque système se
  remplissait de caches : modèles d'IA téléchargés, navigateurs de rendu, paquets Python.
- Ses archives occupaient à elles seules 71 Go sur 105.
- Le nettoyage des vieilles archives (`prune`) ne tourne **qu'après une sauvegarde réussie**. Une
  fois l'espace plein, plus rien ne réussissait, donc plus rien n'était nettoyé : le blocage
  s'entretenait seul.

## La correction, en trois temps

**1. Libérer l'espace**, en supprimant les plus anciennes archives de la VM et en gardant les
deux dernières. La liste est vérifiée d'abord, la suppression lancée ensuite :

```bash
# lister les archives de la VM, sauf les deux plus récentes
pvesm list <stockage> --vmid <id> | awk 'NR>1{print $1}' | sort | head -n -2
# puis, après vérification, les supprimer
pvesm list <stockage> --vmid <id> | awk 'NR>1{print $1}' | sort | head -n -2 | xargs -n1 pvesm free
```

Piège : l'espace libéré n'apparaît dans `pvesm status` qu'avec retard, alors que `df -h` sur le
point de montage le montre tout de suite. Résultat : 57 % d'occupation.

**2. Séparer les sauvegardes en deux tâches.**

| Tâche | Sélection | Rétention |
|---|---|---|
| principale | toutes les VM **sauf** celle de production | celle du stockage (7 / 3 / 2) |
| production | la VM de production seule | 3 jours, réglée sur la tâche |

La tâche principale fonctionne par exclusion : une VM créée demain y entre toujours d'office.

**3. Traiter la cause** : les caches de la VM (environ 7 Go) ont été déplacés sur son disque de
données, exclu des sauvegardes, avec un lien symbolique à l'ancien emplacement. Ils se
retéléchargent au besoin. Disque système de la VM : de 22 à 17 Go.

## Ce qui manquait : l'alerte

Le risque était connu et noté depuis la mise en place : sans relais de messagerie sur l'hôte, un
échec de sauvegarde ne prévient personne. On se croit couvert, ce qui est pire que de se savoir
découvert. Ce risque s'est réalisé.

La décision : une alerte lue dans l'**API Proxmox**, avec un **jeton en lecture seule**, par une
application de supervision qui notifie déjà sur mon poste. Elle signalera une sauvegarde échouée
ou plus vieille que 26 heures. Ni relais de messagerie, ni ouverture du pare-feu.

## Ce que j'en retiens

- Une tâche automatique sans alerte d'échec finit toujours par échouer en silence.
- Un mécanisme de nettoyage qui dépend du succès peut entretenir sa propre panne.
- Ce qui se régénère n'a rien à faire dans une sauvegarde.
