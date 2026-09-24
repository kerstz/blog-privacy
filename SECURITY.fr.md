# Sécurité

[🇬🇧 English](SECURITY.md) · 🇫🇷 Français

> La version de référence est l'anglaise ([SECURITY.md](SECURITY.md), avec le
> détail complet des CVE) ; ce fichier en est la traduction.

## Version sécurité des comptes — septembre 2026 (3)

**Mettez à jour avec `./update.sh`.** Après cette première mise à jour, lancez
une fois `flask encrypt-legacy` (ou laissez la prochaine mise à jour
automatique le faire) pour chiffrer les anciennes données.

### Comptes
- **Changement de mot de passe** (`/account/security`) : demande le mot de passe
  actuel et déconnecte tous les autres appareils.
- **Déconnexion partout** : invalide toutes les autres sessions et cookies « se
  souvenir de moi ».
- **Codes de secours 2FA** : 10 codes à usage unique affichés une seule fois à
  l'activation de la 2FA (seule leur empreinte SHA-256 est stockée), utilisables
  à la place d'un code TOTP ; régénérables après ré-authentification. Perdre son
  téléphone ne bloque plus un admin.
- **Supprimer mon compte** (mot de passe + 2FA + taper DELETE) : messages,
  pièces jointes, likes et notifications effacés, commentaires anonymisés. Le
  dernier admin ne peut pas se supprimer.
- **Télécharger mes données** : export JSON (compte, commentaires, articles,
  messages déchiffrés, likes, notifications), après ré-authentification.
- **La déconnexion se fait en POST avec jeton CSRF** (un site tiers pouvait déconnecter les utilisateurs).

### Chiffrement au repos
- **Les fichiers envoyés (pièces jointes du chat, photos de profil) sont
  chiffrés sur le disque** avec la même clé que les messages, et déchiffrés
  seulement pour un utilisateur autorisé.
- `flask encrypt-legacy` : chiffre les messages et fichiers restés en clair.
  Idempotent ; `update.sh` le lance automatiquement.

### Alertes
- Alertes de sécurité Telegram (si le bot est configuré) : connexions admin
  (et connexions sans 2FA), échecs de mot de passe / 2FA sur un compte admin,
  2FA activée / désactivée, code de secours utilisé ou régénéré, mot de passe
  changé, promotions / rétrogradations / suppressions, suppression de compte.

### Durcissement
- **CSP stricte pour les styles** : tous les blocs `<style>` déplacés dans
  `static/css/pages/*.css` ; `style-src 'self'`. La CI refuse `<style>` dans les templates.
- **Anti-spam sans JS** (inscription, commentaires, contact) : champ piège +
  délai minimum signé, sans captcha ni service tiers.
- **bandit** (analyse statique) dans la CI.
- `update.sh` s'exécute depuis une copie de lui-même et passe la main à la
  nouvelle version juste après le `git pull`.

### Fonctionnalités (sans JavaScript)
- **Catégories et tags** (`/category/<slug>`, `/tag/<slug>`), **recherche**
  (`/search?q=`), **flux RSS** (`/feed.xml`).

### Corrections
- Les articles créés depuis le panneau admin ne pouvaient plus être publiés
  (régression de la version (1)) : corrigé.
- Les extraits d'articles affichaient le BBCode brut.

## Version vie privée & durcissement — septembre 2026 (2)

Suite de la mise à jour de sécurité ci-dessous. **Mettez à jour avec `./update.sh`.**

### Vie privée
- **Plus aucune requête vers des tiers** : Google Fonts remplacé par des polices
  hébergées localement (l'IP de chaque visiteur partait chez Google à chaque page) ;
  liens CDN Bootstrap / Font Awesome supprimés ; l'iframe de don Trocador devient
  un simple lien ; CKEditor (chargé depuis `cdn.ckeditor.com`) supprimé.
- **Les images externes ne sont jamais chargées** (commentaires et articles) :
  elles s'affichent en lien, l'IP des lecteurs ne fuit pas. CSP `img-src 'self' data:`.
- **Tor** : `ONION_ADDRESS` (optionnel) ajoute l'en-tête `Onion-Location` ;
  configuration du service onion dans `deploy/` (via le reverse proxy, pour qu'un
  client Tor ne puisse pas falsifier `X-Forwarded-For`).

### Zéro JavaScript
- Tous les scripts et gestionnaires `onclick` ont été supprimés (défilement du
  chat, confirmations de suppression, filtre des commentaires, menu admin, bouton
  « copier » des dons, éditeur), remplacés par du HTML/CSS pur.
- La CSP impose `script-src 'none'` : même si une faille XSS réapparaissait,
  aucun script ne pourrait s'exécuter.
- Flask-CKEditor supprimé : il servait aussi les fichiers de CKEditor 4.14 (CVE connues).
- Les démos d'interface (avec scripts) sont déplacées de `app/static/` vers `docs/` (plus servies).

### Corrections de sécurité
- **Les codes 2FA pouvaient être refusés sur un serveur hors UTC** : corrigé.
- **Le bouton « supprimer un article » échouait toujours** (jeton CSRF manquant) : corrigé.
- **Limitation de débit et anti-rejeu 2FA persistants** (SQLite,
  `instance/security_state.db`) : ils survivent aux redémarrages et sont partagés
  entre processus.
- `gunicorn` ajouté (serveur de production).

### Exploitation
- `./auto-update.sh enable daily|weekly|monthly|"<cron>"` : mises à jour
  automatiques **optionnelles**, à la fréquence de votre choix (désactivées par défaut).
- `update.sh` : verrou, rien à faire s'il n'y a rien de nouveau, vérification de
  démarrage + tests, **retour arrière automatique** en cas d'échec, redémarrage
  optionnel (`UPDATE_RESTART_CMD`) et notification Telegram.
- `./backup.sh` : sauvegardes chiffrées (gpg AES-256) des bases, uploads et `.env`,
  planification, rétention, copie distante optionnelle, restauration sans risque.
- GitHub Actions : tests + `pip-audit` à chaque push, pull request et chaque lundi ;
  vérification qu'aucun template ne contient de JavaScript ou de ressource tierce.
  Dependabot pour pip et GitHub Actions.
- `deploy/` : service systemd sandboxé, Caddy et nginx sans logs d'accès, service onion Tor.

### Code
- `routes.py` (3 600 lignes) découpé en `routes.py`, `services.py`, `telegram_bot.py` et `mobile_api.py`.
- Templates inutilisés supprimés.
- Tout est en anglais (code, commentaires, interface) ; documentation française dans les fichiers `*.fr.md`.
- Badges par défaut renommés en anglais (renommage en place via `/init_badges`, personne ne perd ni ne regagne un badge).
- L'aide de l'éditeur ne documente plus que les balises BBCode qui existent ; `[list=1]` et `[center]`/`[left]`/`[right]`/`[justify]` ajoutées.

### Notes de mise à jour
- Les articles écrits avec l'ancien éditeur (HTML) restent affichés (nettoyés).
- Les images externes des articles/commentaires existants deviennent des liens.
- Derrière un proxy, relisez `deploy/` (Tor doit passer par le proxy).

## ⚠️ Mise à jour de sécurité — septembre 2026 (1)

Failles critiques corrigées (détail et liste des CVE dans [SECURITY.md](SECURITY.md)) :

- chat privé lisible par tous les utilisateurs ;
- WebSocket sans authentification (usurpation de n'importe quel compte) et diffusion des messages à tous les clients ;
- XSS stockées (commentaires, réponses, chat, panneau admin) ;
- fichiers envoyés publics avec des noms devinables, métadonnées EXIF/GPS mal supprimées ;
- 2FA contournable (brute-force, rejeu, API mobile sans 2FA), PIN Telegram sans limite ;
- brouillons visibles publiquement, messages stockés en clair ;
- redirection ouverte, faux dons, fixation de session, clés faibles acceptées ;
- environ 30 CVE dans 12 dépendances (cryptography, Flask, Werkzeug, Jinja2, python-socketio, urllib3…).

## Rester à jour — régulièrement

De nouvelles failles sont publiées chaque semaine. **Mettez à jour au moins une
fois par mois, et immédiatement en cas de mise à jour de sécurité**, ou laissez
le faire automatiquement :

```bash
./update.sh                          # mettre à jour maintenant
./auto-update.sh enable weekly       # daily | weekly | monthly | "<expression cron>"
./auto-update.sh status
./auto-update.sh disable
```

`update.sh` sauvegarde la base et les uploads dans `backups/`, récupère le code
(fast-forward uniquement), met à jour les dépendances, applique les migrations,
vérifie que l'application démarre (et lance les tests si pytest est installé) et
**revient en arrière** en cas d'échec. Il ne modifie jamais `.env`, le contenu de
la base ni `uploads/`.

Pour les mises à jour sans surveillance, définissez `UPDATE_RESTART_CMD` dans
`.env` (ex. `UPDATE_RESTART_CMD=sudo systemctl restart blog`) et autorisez
exactement cette commande pour l'utilisateur du cron :

```
# /etc/sudoers.d/blog  (éditer avec : sudo visudo -f /etc/sudoers.d/blog)
blog ALL=(root) NOPASSWD: /usr/bin/systemctl restart blog
```

Journal : `logs/update.log` ; avec le bot Telegram configuré, l'admin est prévenu
après chaque mise à jour, échec ou retour arrière.

Vérifier les CVE à tout moment sans rien modifier :

```bash
pip install pip-audit && pip-audit -r requirements.txt
```

## Sauvegardes

```bash
./backup.sh run                     # chiffrée : bases + uploads + .env
./backup.sh enable daily            # daily | weekly | "<expression cron>"
./backup.sh restore <fichier> <dossier>   # déchiffre dans un NOUVEAU dossier
```

`BACKUP_PASSPHRASE` (dans `.env`) est obligatoire : gardez-en une copie hors du
serveur. `BACKUP_KEEP` règle la rétention (14 par défaut), `BACKUP_REMOTE` une
copie distante optionnelle (rsync).

## Check-list production

- `SESSION_COOKIE_SECURE=true` et **HTTPS uniquement** (active HSTS + cookie `__Host-`).
- `SECRET_KEY`, `ENCRYPTION_KEY`, `ENCRYPTION_SALT` aléatoires et forts. **Sauvegardez** `ENCRYPTION_KEY`/`ENCRYPTION_SALT` (`./backup.sh` inclut `.env`).
- Derrière Caddy/nginx : `TRUSTED_PROXY_COUNT=1`. Faites aussi passer Tor par le proxy (voir `deploy/torrc.example`).
- Utilisez le service systemd fourni (`deploy/blog.service`) : utilisateur dédié, sandbox, un worker gunicorn avec des threads.
- Activez la 2FA sur tous les comptes admin ; `TELEGRAM_ADMIN_USER_ID` et `TELEGRAM_ADMIN_PIN` si vous utilisez le bot.
- Activez les sauvegardes chiffrées planifiées et, idéalement, les mises à jour automatiques.
- Jamais de mode debug Flask.

## Limites connues

- `style-src 'unsafe-inline'` reste nécessaire (blocs `<style>` et attributs `style` dans les templates). Les scripts sont entièrement bloqués.
- Le poller Telegram tourne dans le processus : un seul worker gunicorn (montez en charge avec des threads).
- `[img]` uniquement pour les images hébergées sur le blog ; pas encore d'interface de bibliothèque d'images.
- Le fichier de base de données n'est pas chiffré lui-même (les messages et les
  fichiers le sont) : utilisez le chiffrement du disque du serveur.
- Pas de réinitialisation de mot de passe par email (aucun email n'est stocké,
  par choix) : un utilisateur qui oublie son mot de passe doit demander à un admin.

## Signaler une faille

Ouvrez une « security advisory » privée sur GitHub plutôt qu'une issue publique.
