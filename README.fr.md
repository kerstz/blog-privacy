# TechBlog

[🇬🇧 English](README.md) · 🇫🇷 Français

> La version de référence est l'anglaise ([README.md](README.md)) ; ce fichier en est la traduction.

> **⚠️ Mises à jour de sécurité (septembre 2026) :** failles critiques corrigées,
> toutes les dépendances mises à jour au-delà de leurs CVE, le site fonctionne
> désormais **sans aucun JavaScript et sans aucune requête vers des tiers**.
> **Mettez à jour avec `./update.sh`, ou activez les mises à jour automatiques
> (`./auto-update.sh enable weekly`).** Détails dans [SECURITY.fr.md](SECURITY.fr.md).

> **Vibe coded.** Ce projet a été développé avec une forte assistance d'outils
> d'IA. Il a été relu et il est couvert par des tests de sécurité, mais lisez le
> code avant de lui confier quoi que ce soit de sensible, et signalez toute anomalie.

Un blog axé sur la vie privée, construit avec Flask. Pas de JavaScript, pas de
traqueurs, pas de polices ni de CDN tiers : il fonctionne dans Tor Browser au
niveau « Le plus sûr » et peut être servi en site `.onion`.

## Fonctionnalités

- **Aucun JavaScript** : toutes les pages fonctionnent JS désactivé (la CSP impose même `script-src 'none'`)
- **Aucune requête vers des tiers** : polices hébergées localement, pas de CDN, pas de widget intégré, images externes affichées en lien
- **Prêt pour Tor** : en-tête `Onion-Location`, configuration du service onion dans `deploy/`
- **Articles** en BBCode (ou HTML simple), brouillons, publication programmée, révisions
- **Commentaires imbriqués**, likes, notifications, XP, niveaux et badges
- **Chat privé chiffré** entre chaque utilisateur et l'admin
- **Double authentification TOTP**
- **Bot Telegram d'administration** (optionnel) et **API mobile admin**
- **Pages statiques, bannières, contact, dons en crypto** (QR codes générés côté serveur)
- **Mises à jour sûres** : `./update.sh` (sauvegarde, mise à jour, vérification, retour arrière automatique), mises à jour automatiques optionnelles à la fréquence de votre choix, sauvegardes chiffrées

## Démarrage rapide

```bash
git clone https://github.com/kerstz/blog-privacy.git
cd blog-privacy
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # puis remplir les secrets
flask db upgrade
python create_admin.py
python wsgi.py              # serveur de dev sur http://127.0.0.1:5000
```

Générez chaque secret du `.env` avec :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

L'application refuse de démarrer si un secret manque ou vaut la valeur d'exemple.
**Sauvegardez `ENCRYPTION_KEY` et `ENCRYPTION_SALT`** : sans elles, l'historique du
chat ne pourra plus jamais être déchiffré.

## Production

Des fichiers prêts à l'emploi sont dans [`deploy/`](deploy/) :

| Fichier | Rôle |
|---------|------|
| `blog.service` | service systemd : utilisateur dédié sans privilèges, sandbox, gunicorn sur 127.0.0.1 |
| `Caddyfile` | reverse proxy avec HTTPS automatique, sans logs d'accès |
| `nginx.conf` | reverse proxy alternatif (avec certbot) |
| `torrc.example` | service onion (puis renseigner `ONION_ADDRESS` dans `.env`) |

Dans `.env` : `SESSION_COOKIE_SECURE=true` (HTTPS) et `TRUSTED_PROXY_COUNT=1`
(derrière le reverse proxy). Activez la 2FA sur tous les comptes admin.

## Mises à jour (important)

De nouvelles failles sont publiées chaque semaine. **Gardez le blog à jour.**

```bash
./update.sh                          # mettre à jour maintenant
./auto-update.sh enable weekly       # mises à jour automatiques : daily | weekly | monthly | "<cron>"
./auto-update.sh status
./auto-update.sh disable
```

`update.sh` sauvegarde la base et les uploads, récupère le code (fast-forward
uniquement), met à jour les dépendances, applique les migrations, vérifie que
l'application démarre (et lance les tests si pytest est installé), et **revient
automatiquement en arrière** en cas d'échec. Il ne touche jamais au contenu de la
base, à `uploads/` ni au `.env`. Les mises à jour automatiques sont **désactivées
par défaut** ; si `UPDATE_RESTART_CMD` est défini dans `.env`, l'application est
redémarrée après chaque mise à jour réussie, et le bot Telegram (s'il est
configuré) vous prévient.

## Sauvegardes

```bash
./backup.sh run                     # sauvegarde chiffrée : bases + uploads + .env
./backup.sh enable daily            # daily | weekly | "<cron>"
./backup.sh restore <fichier> <dossier>   # déchiffre dans un NOUVEAU dossier
```

Définissez `BACKUP_PASSPHRASE` dans `.env` et gardez-en une copie hors du serveur.
`BACKUP_REMOTE` (optionnel) copie chaque sauvegarde ailleurs avec rsync.

## Écrire des articles

Articles, commentaires et réponses utilisent le BBCode (voir `/editor_help` sur
votre blog). Les images externes (`[img]https://...[/img]`) sont affichées en lien
et jamais chargées : l'IP des lecteurs n'est jamais envoyée à d'autres sites.
Pour intégrer une image, envoyez-la sur le blog.

## API mobile admin

Authentification HTTP Basic avec un compte admin ; si la 2FA est activée, ajoutez
le code du moment dans l'en-tête `X-TOTP-Code`. Liste des routes dans le
[README anglais](README.md#admin-mobile-chat-api).

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q tests/
pip-audit -r requirements.txt
```

Les mêmes vérifications tournent sur GitHub Actions à chaque push et chaque lundi,
et Dependabot ouvre des pull requests pour les mises à jour de dépendances.

## Sécurité

Voir [SECURITY.fr.md](SECURITY.fr.md).

## Licence

MIT.
