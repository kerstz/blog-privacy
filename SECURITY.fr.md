# Sécurité

[🇬🇧 English](SECURITY.md) · 🇫🇷 Français

> La version de référence est l'anglaise ([SECURITY.md](SECURITY.md), avec le
> détail complet des CVE) ; ce fichier en est la traduction.

## Version d'audit production - novembre 2026 (2)

**Lisez d'abord la note de mise à jour : `./update.sh` ne pouvait pas installer
cette version tout seul.**

### Note de mise à jour (étape manuelle, une fois)

`update.sh` s'arrêtait juste après sa sauvegarde à chaque vraie mise à jour (voir
plus bas) : une installation qui comptait sur lui, ou sur `auto-update.sh`, n'a
reçu aucune des versions publiées depuis. Mettez à jour une fois à la main, puis
`update.sh` refonctionne :

```bash
cd /srv/blog                       # votre copie
git fetch
GNUPGHOME="$UPDATE_GPG_HOME" git verify-commit origin/main   # si vous signez/vérifiez
git merge --ff-only origin/main
./update.sh                        # sauvegarde, dépendances, migrations, tests, redémarrage
```

### Correctifs de sécurité
- **Les commentaires pouvaient injecter des attributs (injection HTML stockée).**
  Une balise BBCode écrite dans une URL (`[url]http://a/[img]...[/img][/url]`)
  était développée ensuite à l'intérieur du `href` généré et en cassait les
  guillemets : tout compte inscrit pouvait donner un `style` à un lien (par
  exemple un lien invisible pleine page vers un autre site). Les URL encodent
  désormais `[`/`]`, et les commentaires passent par la liste blanche `nh3` à
  l'affichage. Une ligne de balises `[url=...]` non fermées coûtait aussi environ
  3 s de CPU par affichage (retour arrière cubique) : corrigé.
- **Les visiteurs Tor derrière un proxy de confiance partageaient un seul verrou.**
  Avec `TRUSTED_PROXY_COUNT` et Tor passant par Caddy/nginx (le montage
  documenté), chaque visiteur onion valait `127.0.0.1` mais était traité comme
  un client identifiable : cinq mauvais mots de passe de n'importe qui bloquaient
  la connexion de tous les utilisateurs Tor, admins compris. Une adresse de
  boucle locale n'identifie plus jamais un client. Les limites anonymes de la
  recherche et du contact sur un onion sont un plafond partagé (x20).
- **Force brute 2FA.** En plus des limites courtes (5 codes par 5 ou 15 min),
  chaque code faux (connexion, ré-authentification, désactivation 2FA, API
  mobile) compte dans un plafond de 20 par compte et par jour ; au-delà le code
  n'est même pas vérifié et une alerte est journalisée. `flask unlock <pseudo>`
  le lève.
- **Sauvegardes : une archive forgée était restaurée.** `gpg -d` sort aussi un
  message OpenPGP *non chiffré* sans demander de phrase secrète : une sauvegarde
  remplacée par un tel fichier (copie hors site, `backups/`) était restaurée par
  `backup.sh restore` et par le retour arrière de mise à jour sans aucun
  contrôle. Les deux exigent maintenant le statut gpg `DECRYPTION_OKAY`.
- **Les pièces jointes ne touchent plus le disque en clair.** Le fichier
  d'origine (photo avec ses balises EXIF/GPS) était écrit dans `uploads/`, puis
  ré-encodé, chiffré et supprimé : récupérable sur le disque. Tout se passe
  maintenant en mémoire. Les JPEG sont décodés en taille réduite.
- **Dates publiques sans heure.** Articles, commentaires et flux RSS affichaient
  la minute de chaque commentaire (fuseau horaire, habitudes). Les pages
  publiques n'affichent plus que le jour ; `PUBLIC_TIME_PRECISION=minute`
  rétablit l'ancien affichage.
- **`Server: gunicorn`** partait sur chaque réponse (gunicorn ignore la valeur de
  l'application) : un service onion servi directement par gunicorn annonçait sa
  pile logicielle. `wsgi.py` fait maintenant envoyer `Server: server`.
- Le secret 2FA en attente est chiffré dans le cookie de session (lisible) ; HSTS
  n'est jamais envoyé à un nom `.onion` ni à une sonde locale ;
  `Permissions-Policy` refuse `browsing-topics` ; un commentaire sur un article
  repassé en brouillon n'est plus modifiable.

### Exploitation
- **`update.sh` n'allait jamais au bout d'une mise à jour** : le `ls` de rétention
  sur trois motifs échouait sous `set -o pipefail` et `make_backup || exit 1`
  arrêtait tout. `backup.sh run` sortait en erreur de la même façon, avant la
  rétention et la copie hors site (`BACKUP_REMOTE`).
- `backup.sh` fonctionne avec l'installation `deploy/deploy-onion.sh` :
  `BLOG_ENV_FILE` (secrets dans `/etc`), `BACKUP_DIR`, `uploads/` en lien
  symbolique copié par son contenu (l'archive contenait un lien mort et aucune
  pièce jointe).
- `deploy/package.sh` et `deploy-onion.sh` n'emportent jamais `backups/` ni `logs/`.
- Les tests n'écrivent plus dans `uploads/` ni `instance/quarantine` du projet
  (`UPLOAD_DIR`, `QUARANTINE_DIR`) ; la chaîne Alembic est testée sur une base
  vierge en CI.
- Dépendances : alembic 1.20.1, click 8.5.1, cryptography 50.0.2, MarkupSafe
  3.0.4, python-dotenv 1.2.4 (dév. : pytest 9.2.0, ruff 0.17.4) ; actions GitHub
  checkout v7.0.1 / setup-python v7.1.0. `pip-audit` et `osv-scanner` : rien.

### Nouveautés
- **Rotation de clé** : `flask rotate-key` (voir *Changer la clé de chiffrement*).
- **Conservation** : `flask purge-messages --days N`, `flask purge-notifications`.
- **Mode maintenance** : `flask maintenance on|off|status` ou le tableau de bord admin.
- **Flux RSS par étiquette et par catégorie** ; **export Markdown** de tous les articles.

## Changer la clé de chiffrement

Après une fuite supposée d'`ENCRYPTION_KEY`, ou pour passer une installation
existante à 600000 itérations PBKDF2 (même clé, nouvelles itérations) :

1. `./backup.sh run` (et gardez le `.env` actuel en lieu sûr).
2. Dans `.env`, recopiez les valeurs actuelles dans `ENCRYPTION_OLD_KEY`,
   `ENCRYPTION_OLD_SALT`, `ENCRYPTION_OLD_ITERATIONS`, puis mettez les nouvelles
   `ENCRYPTION_KEY` / `ENCRYPTION_SALT` / `ENCRYPTION_ITERATIONS=600000`.
3. Redémarrez l'application : elle lit les deux clés et écrit avec la nouvelle.
4. `flask rotate-key --dry-run`, puis `flask rotate-key` : messages, secrets 2FA
   et toutes les pièces jointes `.enc` sont rechiffrés avec la nouvelle clé. La
   commande s'arrête en erreur si quelque chose est illisible : n'allez pas plus
   loin dans ce cas.
5. Retirez les trois lignes `ENCRYPTION_OLD_*`, redémarrez, lancez `./backup.sh run`.

## Version d'audit - novembre 2026

**Mettez à jour avec `./update.sh`.**

- **Pillow 12.3.0 -> 13.0.0** : 39 avis de sécurité (décodeurs TIFF, JPEG, GIF,
  BMP, etc.) corrigés en 13.0.0. Les images envoyées sont décodées par Pillow :
  cette mise à jour est importante. Les dépendances de développement `certifi`
  et `filelock` sont aussi mises à jour. `pip-audit` et `osv-scanner` sont propres.
- **Contrôle d'accès aux pièces jointes** : `_` et `%` dans un nom de fichier
  demandé n'agissent plus comme jokers SQL `LIKE` (défense en profondeur).
- **Profil public** : les « commentaires récents » n'affichent plus les
  commentaires faits sur des articles repassés en brouillon (fuite de titres).
- **`/healthz`** : sonde anonyme de vie + base de données (`ok` / `unavailable`).
- **Compteurs du profil public** : `total_comments` et la liste ne comptent plus que
  les commentaires non supprimés d'articles publiés (avant : tous).
- **`deploy/blog.service`** : isolation systemd renforcée ; le dossier de
  sauvegardes facultatif ne bloque plus le démarrage s'il est absent.

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
- Alertes de sécurité (écrites dans le journal de l'application ; l'ancien relais Telegram a été retiré) : connexions admin
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
- **Plus aucune requête vers des tiers** : Google Fonts supprimé (pile de polices
  système, rien n'est chargé chez un tiers) (l'IP de chaque visiteur partait chez Google à chaque page) ;
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
  optionnel (`UPDATE_RESTART_CMD`) ; les messages d'état vont dans le journal.
- `./backup.sh` : sauvegardes chiffrées (gpg AES-256) des bases, uploads et `.env`,
  planification, rétention, copie distante optionnelle, restauration sans risque.
- GitHub Actions : tests + `pip-audit` à chaque push, pull request et chaque lundi ;
  vérification qu'aucun template ne contient de JavaScript ou de ressource tierce.
  Dependabot pour pip et GitHub Actions.
- `deploy/` : service systemd sandboxé, Caddy et nginx sans logs d'accès, service onion Tor.

### Code
- `routes.py` (3 600 lignes) découpé en `routes.py`, `services.py`, `mobile_api.py` et `cli.py`.
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

Journal : `logs/update.log` (chaque mise à jour, échec ou retour arrière y est consigné)
après chaque mise à jour, échec ou retour arrière.

Vérifier les CVE à tout moment sans rien modifier :

```bash
pip install --require-hashes -r requirements-dev.lock && pip-audit -r requirements.lock --require-hashes --disable-pip --strict
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
- Utilisez le service systemd fourni (`deploy/blog.service`) : utilisateur dédié, sandbox, un worker gunicorn avec des threads. Sur Tor, activez `HiddenServicePoWDefensesEnabled 1` (Tor 0.4.8+, dans `deploy/torrc.example`).
- Activez la 2FA sur tous les comptes admin.
- Activez les sauvegardes chiffrées planifiées et, idéalement, les mises à jour automatiques.
- Jamais de mode debug Flask.

## Modèle de menace

L'adversaire nominal est un visiteur anonyme sur Tor : aucune IP client
(tout arrive de `127.0.0.1`), et créer des comptes, publier ou deviner des mots
de passe est gratuit. Les contrôles sont par compte (verrou de connexion, 2FA,
limites de débit), pas par IP ; le verrou par client est ignoré quand l'IP n'est
pas significative. `flask unlock <pseudo>` (`--all`) lève un verrou. L'API mobile
admin est **désactivée par défaut** (`MOBILE_API_ENABLED=false`) et exige le TOTP
pour les admins. Les messages de contact sont visibles dans `/admin/contact` et
à purger régulièrement (`flask purge-contact --days 90`).

Chaîne d'approvisionnement : Python 3.12+, dépendances installées avec
`pip install --require-hashes -r requirements.lock` ; actions CI épinglées par SHA.

## Limites connues

- Les images sont ré-encodées (aucune métadonnée ne survit) ; les autres pièces
  jointes (PDF, bureautique, vidéos) sont chiffrées au repos mais **pas**
  nettoyées : leurs métadonnées (nom de l'auteur, logiciel, GPS des vidéos)
  arrivent chez le destinataire. Nettoyez-les avant envoi.
- Werkzeug écrit un envoi de plus de 500 Ko dans un fichier temporaire pendant
  la lecture de la requête (`PrivateTmp=true` comme dans `deploy/blog.service`,
  et chiffrement du disque).
- `style-src-attr 'unsafe-inline'` reste nécessaire pour les attributs `style=""` (couleurs et tailles BBCode assainies) ; les éléments `<style>` sont bloqués (`style-src 'self'`). Les scripts sont entièrement bloqués.
- Les flux SSE vivent dans le processus : un seul worker gunicorn (montez en charge avec des threads).
- `[img]` uniquement pour les images hébergées sur le blog ; pas encore d'interface de bibliothèque d'images.
- Le fichier de base de données n'est pas chiffré lui-même (les messages et les
  fichiers le sont) : utilisez le chiffrement du disque du serveur.
- Pas de réinitialisation de mot de passe par email (aucun email n'est stocké,
  par choix) : un utilisateur qui oublie son mot de passe doit demander à un admin.

## Signaler une faille

Ouvrez une « security advisory » privée sur GitHub plutôt qu'une issue publique.
