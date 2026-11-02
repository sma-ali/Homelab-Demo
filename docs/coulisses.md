# Les coulisses de cette vitrine

Montrer un vrai serveur sans donner de quoi l'atteindre : les adresses, les ports, les noms de
machines, les versions exactes ne doivent jamais apparaître, ni dans le texte, ni dans une
image, ni dans une seule image d'une vidéo. Plutôt que de compter sur ma vigilance, j'ai
construit une chaîne qui rend la fuite impossible à commettre par inadvertance.

## 1. Une liste noire, hors du dépôt

Un script parcourt le dépôt privé du homelab, **historique git compris** (une valeur effacée
d'une doc vit encore dans un ancien commit), ainsi que la configuration SSH du poste. Il en
extrait les adresses IPv4 et IPv6, les plages réseau, les ports, les domaines, les noms d'hôtes,
les UUID, les clés et leurs empreintes. J'y ajoute à la main ce qu'un script ne devine pas :
noms des VM, offre et datacenter de l'hébergeur, versions exactes.

Cette liste ne vit jamais dans ce dépôt : publier la liste des secrets serait les publier.

## 2. Un masque dans le navigateur, avant de filmer

Flouter après coup laisse toujours passer quelque chose : une image oubliée, un flou
réversible. Ici, la vraie valeur n'est **jamais à l'écran**. Une petite extension de navigateur
remplace chaque valeur sensible par une valeur factice (plages d'adresses réservées à la
documentation, domaine `exemple.lab`) :

- **avant le rendu** : les remplacements passent par un `MutationObserver`, dont les rappels
  s'exécutent avant que le navigateur ne dessine la page, y compris pour le contenu qui arrive
  plus tard (journaux de tâches, infobulles, cadres intégrés) ;
- **au-delà de la liste** : toute adresse IP, MAC ou IPv6, tout e-mail, clé ou numéro de
  version est remplacé d'office, même s'il n'est pas dans la liste noire ;
- **sans rien casser** : les champs de formulaire ne sont jamais modifiés, une valeur sensible y
  est seulement affichée en points. Rien de faux ne peut être enregistré dans la configuration ;
- **avec un filet** : si une valeur sensible reste visible malgré tout (par exemple coupée en
  deux morceaux de texte), la page entière est recouverte d'un écran noir. La prise est à refaire.

## 3. Un contrôle avant chaque commit

Un hook git refuse tout commit qui contient une valeur de la liste noire, ou une valeur
interdite d'office (adresse hors plage de documentation, MAC, e-mail, clé). Il vérifie :

- **le texte** de chaque fichier, et la version réellement indexée ;
- **les images**, par OCR (Tesseract), sur l'image et sur une version agrandie ;
- **les vidéos**, par OCR de **chaque image**, en parallèle sur tous les cœurs ;
- **les métadonnées**, en comparant chaque fichier à sa version vidée par exiftool ;
- **le son** : une vidéo de la vitrine doit être muette ;
- **la signature de l'encodeur**, que x264 inscrit dans le flux vidéo lui-même et qui trahit sa
  version ;
- **l'auteur du commit** : sur GitHub, l'e-mail de chaque commit est public.

gitleaks complète le tout pour les secrets classiques (jetons, clés d'API), et la même
vérification, sans la liste privée, tourne dans la CI GitHub à chaque envoi.

## 4. Des tests avec de fausses fuites

Un garde-fou qu'on n'a jamais vu échouer ne prouve rien. Les tests lui soumettent de fausses
fuites, et vérifient qu'il les attrape toutes :

- un nom de machine affiché **0,4 seconde** au milieu d'une vidéo ;
- une adresse dans une capture d'écran, un commentaire caché dans un PNG ;
- une piste audio, une signature d'encodeur ;
- dans un vrai Chromium, du contenu ajouté après le chargement, un cadre intégré, une adresse
  coupée en deux.

Les fichiers propres, eux, doivent passer : un garde-fou qui crie au loup finit désactivé.

## Ce que la chaîne a attrapé en route

- **Mon adresse e-mail personnelle** dans l'auteur des commits, remplacée par l'adresse anonyme
  de GitHub avant le premier envoi.
- **Un code de double authentification** à l'écran au début d'une prise : coupé au montage.
- **Une date de compilation du noyau** restée visible après le retrait de son numéro de
  version : elle suffisait à le retrouver. Ajoutée au masque.
- **Une fausse alerte instructive** : sur un GIF trop tramé, l'OCR a lu l'adresse factice
  `2001:db8::` comme une vraie adresse. Plutôt que d'affaiblir le contrôle, j'ai rendu le GIF
  plus net.
