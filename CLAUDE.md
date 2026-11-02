# homelab_demo

Vitrine publique du homelab d'Ali : ce qu'il a construit, pourquoi, et à quoi ça ressemble, en texte, images et courts extraits vidéo. Aucune donnée qui permette d'atteindre ou de cartographier la vraie infrastructure. Le dépôt sera public : rien de privé dans ce fichier, le contexte privé est dans `CLAUDE.local.md` (ignoré par git).

## Ce que montre la vitrine

- Un README qui raconte le projet : serveur dédié sous Proxmox, pare-feu OPNsense, accès uniquement par VPN WireGuard, durcissement (pare-feu de l'hôte en IPv4 et IPv6, 2FA, SSH par clé ; CrowdSec étudié puis différé, jamais présenté comme en place), sauvegardes avec restauration testée.
- Un schéma d'architecture simplifié, aux noms génériques.
- Les choix argumentés, sous forme de courtes fiches de décision.
- Des procédures génériques (restauration d'une VM, ajout d'un pair WireGuard), avec des valeurs fictives.
- La VM de production (chaînes vidéo automatisées), sous ce nom générique.
- Des démos de 10 à 20 s : tableau de bord Proxmox, accès refusé sans VPN puis accordé avec, sauvegarde puis restauration d'une VM, vue d'ensemble des règles du pare-feu.

## Ce qui n'y entre jamais

IP, plages réseau, ports, noms de domaine, noms d'hôtes, adresses MAC, identifiants ou numéros de compte chez l'hébergeur, noms d'utilisateurs, empreintes de clés, exports de configuration, versions exactes des logiciels.

## Méthode pour les images et les vidéos

1. Remplacer avant de filmer : un script injecté dans le navigateur remplace à l'écran chaque valeur sensible par une valeur factice (plages de documentation RFC 5737 comme `203.0.113.0/24`, domaine `exemple.lab`). La vraie valeur n'est jamais à l'écran.
2. Terminal enregistré en texte (asciinema), nettoyé et vérifié comme un fichier texte, puis converti en animation.
3. En dernier recours, rectangle plein et opaque, appliqué dans le fichier final aplati. Jamais de flou ni de pixelisation.
4. Fenêtre seule à l'image : pas de bureau, d'onglets, de notifications, de visage ni de voix.
5. Métadonnées supprimées de chaque image et vidéo.

## Garde-fou

- Une liste noire des valeurs sensibles, tirée du dépôt privé, vit HORS de ce dépôt (chemin dans `CLAUDE.local.md`).
- Un script de contrôle cherche ces valeurs dans tous les fichiers texte, et dans le texte lu par OCR sur chaque image et chaque image extraite des vidéos. Une seule correspondance bloque le commit.
- gitleaks en pré-commit et en CI.
- Le dépôt reste privé jusqu'à la relecture complète par Ali.

## Règles d'écriture

- Docs et commentaires en français ; identifiants du code en anglais.
- Commits Conventional, forme sèche, en minuscules, sans point final. Aucune attribution d'IA.
- Jamais de tiret cadratin ni de demi-cadratin comme ponctuation.

## Outils

- `tools/build_blacklist.py` : régénère la liste noire (hors dépôt) depuis les sources privées, sans toucher à la partie manuelle.
- `tools/check_leaks.py` : le contrôle (texte, OCR des images et des vidéos, métadonnées, piste audio, e-mail d'auteur). Lancé par `.githooks/` (activer avec `git config core.hooksPath .githooks`).
- `tools/mask/` + `tools/build_mask.py` : le masque de tournage, une extension Chrome assemblée hors dépôt avec les vraies valeurs ; `tools/film.sh` ouvre la fenêtre de tournage.
- `tools/terminal_mask.py` + `tools/scene.sh` + `tools/export_cast.sh` : les plans de terminal, enregistrés avec asciinema ; la sortie passe par le masque de terminal avant l'écran, puis l'export vérifie le texte et chaque image du GIF.
- Tests : `python3 -m unittest discover -s tests` et `npm test` (masque dans Chromium). Toujours avec de fausses valeurs.
