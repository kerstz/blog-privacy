# depressedyoungmanblog

English · [Français](README.fr.md)

A small, self-hosted personal blog that tries hard not to know who its readers
are. It is a Flask + SQLite application with posts, nested comments, a private
chat between each reader and the site owner, and an admin panel, and it works
entirely without JavaScript and without loading anything from a third party.
It is designed to be served as a Tor onion service, but runs just as well
behind an ordinary HTTPS reverse proxy.

> **Vibe coded.** This project was built with heavy help from AI coding tools.
> It has been reviewed and is covered by security regression tests, but read the
> code before trusting it with anything sensitive, and report anything odd.

> **Security updates:** dependencies are pinned past their known CVEs. Update
> with `./update.sh`, or turn on automatic updates
> (`./auto-update.sh enable weekly`). Changelog in [SECURITY.md](SECURITY.md).

## Contents

- [Privacy model](#privacy-model)
- [Screenshots](#screenshots)
- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Updates and backups](#updates-and-backups)
- [Mobile admin API](#mobile-admin-api)
- [Security notes](#security-notes)
- [Tests and CI](#tests-and-ci)
- [Project layout](#project-layout)
- [Licence](#licence)

## Privacy model

**Who it is for.** A single owner who writes, and readers who may want to stay
anonymous, including towards the owner's hosting provider and any site the
blog links to.

### What it protects

- **No JavaScript.** Every page is plain HTML and CSS. The Content Security
  Policy sets `script-src 'none'` and `style-src 'self'`, so the site works in
  Tor Browser at the "Safest" level and an injected script would not run.
- **No third-party requests.** No CDN, no web fonts (system font stack), no
  analytics, no embedded widgets. External images in posts and comments are
  shown as links and never loaded (`img-src 'self' data:`). Outgoing links
  carry `rel="noreferrer"` and the site sends `Referrer-Policy: no-referrer`.
  The donation page links to an external swap service; it is labelled as a
  third party and only contacted if the reader clicks.
- **No IP addresses in the logs by default.** A logging filter replaces client
  addresses with `[ip]` in the Werkzeug and application logs (loopback is
  kept). `LOG_CLIENT_IP=true` turns this off for debugging.
- **The rate limiter stores no addresses or usernames.** Its SQLite state file
  only holds HMAC-SHA256 hashes of its keys, keyed from `SECRET_KEY`.
- **Encryption at rest** (Fernet, key derived with PBKDF2-SHA256 from
  `ENCRYPTION_KEY` + `ENCRYPTION_SALT`) for: chat messages, every uploaded
  file (chat attachments and profile pictures, stored as `.enc` under random
  names), and TOTP secrets.
- **Image metadata removed.** Uploaded images are re-encoded to WebP (longest
  side at most 1600 px), which drops EXIF, GPS, XMP and similar blocks.
- **Accounts need only a username and a password.** No e-mail address is asked
  at registration.
- **Strong authentication.** bcrypt password hashes; optional TOTP 2FA per
  account with 10 one-time recovery codes (only their SHA-256 is stored);
  TOTP codes cannot be replayed.
- **Brute-force limits.** Login failures are counted per username (10 per 15
  min) and per client (5 per 5 min); 2FA codes are limited to 5 attempts per 5
  min per account; forms, comments, chat, search and uploads are rate limited.
  A failed login always costs one bcrypt check, so timing does not reveal which
  usernames exist.
- **Session control.** Changing the password, changing a role or using "log out
  everywhere" invalidates every other session and "remember me" cookie. Session
  cookies are `HttpOnly`, `SameSite=Strict`, `Secure` by default and named
  `__Host-sid` (sessions last 4 hours, "remember me" 7 days).
- **Reader control over their data.** From `/account/security` a reader can
  download a JSON export of their data or delete their account (messages,
  attachments, likes and notifications are erased, comments anonymised).

### What it does not protect

- **Encryption is at rest, not end to end.** The key lives on the server next
  to the database. It protects a stolen copy of the database file alone; it
  does not protect against someone who controls the running server, or a legal
  demand made to its operator. Tell readers "encrypted at rest".
- **Not everything is encrypted.** Posts, comments, usernames, profiles and
  contact-form messages (name, e-mail, text) are stored in clear text in the
  database.
- **Non-image attachments are not cleaned.** PDF, office files, archives and
  media are encrypted at rest but their own metadata is left as is.
- **The host machine.** The app does not encrypt the disk or the swap; see
  [deploy/README.md](deploy/README.md) for what the onion deployment does and
  does not cover.
- **Readers' own setup.** A reader who does not use Tor is still visible to
  their network and to the server's reverse proxy.

[docs/ANONYMAT.md](docs/ANONYMAT.md) (French) is the detailed privacy audit:
what was found, what was fixed and what is still open.

## Screenshots

Real pages of the running app, captured on a throwaway database filled with
fake demo data (no real users or posts).

### Public site

**Home page: intro and latest posts**

![Home page: intro and latest posts](docs/screenshots/home.png)

**Post with category, tags, likes and nested comments**

![Post with category, tags, likes and nested comments](docs/screenshots/post.png)

**About page (default text)**

![About page (default text)](docs/screenshots/about.png)

**Donation page: supporter list (empty here) and anonymous swap instructions**

![Donation page: supporter list (empty here) and anonymous swap instructions](docs/screenshots/donate.png)

**Home page on a phone (390 px wide)**

![Home page on a phone (390 px wide)](docs/screenshots/mobile-home.png)

### Accounts and security

**Sign-in form**

![Sign-in form](docs/screenshots/login.png)

**Account creation: username and password only**

![Account creation: username and password only](docs/screenshots/register.png)

**Account security page (top): change password, 2FA status and recovery codes**

![Account security page (top): change password, 2FA status and recovery codes](docs/screenshots/account-security.png)

**One-time 2FA recovery codes, shown once (demo values)**

![One-time 2FA recovery codes, shown once (demo values)](docs/screenshots/recovery-codes.png)

### Admin

**Admin overview: what is waiting, shortcuts, site numbers**

![Admin overview: what is waiting, shortcuts, site numbers](docs/screenshots/admin-dashboard.png)

**Admin side of the encrypted chat: reader list and conversation**

![Admin side of the encrypted chat: reader list and conversation](docs/screenshots/chat.png)

**Site-text editor: every fixed text in English and French**

![Site-text editor: every fixed text in English and French](docs/screenshots/admin-texts.png)

**Moderation: block list, refused uploads, banned accounts (demo entries)**

![Moderation: block list, refused uploads, banned accounts (demo entries)](docs/screenshots/moderation.png)

## Features

- **Posts** written in BBCode (or basic HTML, sanitised with `nh3`), drafts,
  scheduled publishing, a saved revision on every edit, categories (`/category/<slug>`) and tags
  (`/tag/<slug>`), search (`/search?q=`), RSS feed (`/feed.xml`). BBCode help
  is at `/editor_help`.
- **Comments**: nested replies, BBCode rendered server-side, likes on posts and
  comments, notifications.
- **Private chat** between each reader and the admins, with attachments; both
  are encrypted at rest. In the browser it is a plain form; the admin
  conversation page reloads itself (meta refresh with a short server-side wait)
  so new messages appear without JavaScript. Socket.IO events and the mobile
  API stream are available to clients that use them.
- **Bilingual interface** (English / French, `?lang=`), with every fixed text
  editable from the admin panel, with history, revert, and JSON export/import.
- **Image moderation**: flagging an attachment bans its sender, moves the file
  to `instance/quarantine/` and records its SHA-256 and perceptual hash; later
  uploads of the same image, including re-encoded or resized copies, are
  refused.
- **Account security page**: change password, 2FA setup and removal, recovery
  codes, log out everywhere, data export, account deletion. Sensitive actions
  ask for the password again (and the 2FA code when enabled).
- **No-JS anti-spam** on registration, comments and contact: honeypot field
  and a signed minimum form age, no captcha.
- **Gamification**: XP, levels and badges awarded automatically.
- **Admin panel**: overview of what is waiting, posts, static pages, banners,
  users (promote, demote, delete), comments, moderation, site texts,
  statistics.
- **Contact form and donation page.** Contact messages are stored in the
  database (the overview shows the unread count; there is no page to read them
  in this version). On the donation page a visitor can declare an amount,
  recorded as "Anonymous"; the five largest are listed.
- **Mobile admin API** (HTTP Basic Auth + TOTP header, SSE stream), can be
  switched off.
- **Operations scripts**: safe updater with rollback, optional scheduled
  updates, encrypted backups.

## Quick start

Requires Python 3 (CI uses 3.12).

```bash
git clone https://github.com/kerstz/blog-privacy.git
cd blog-privacy
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill SECRET_KEY, ENCRYPTION_KEY and ENCRYPTION_SALT, one value each:
python -c "import secrets; print(secrets.token_urlsafe(48))"
# For local development over plain HTTP, also set SESSION_COOKIE_SECURE=false

flask db upgrade              # create / migrate the database
python create_admin.py        # first time: create an admin account
python wsgi.py                # development server on http://127.0.0.1:5000
```

The app refuses to start if a required secret is missing, still set to
`change_me`, or too short (`SECRET_KEY` under 32 characters, the encryption
values under 16). On a fresh install, also set `ENCRYPTION_ITERATIONS=600000`.

**Back up `ENCRYPTION_KEY`, `ENCRYPTION_SALT` and `ENCRYPTION_ITERATIONS`.**
Without the exact same values, chat messages, uploads and TOTP secrets can
never be decrypted again.

## Configuration

All settings are environment variables, usually read from `.env` (see
[.env.example](.env.example)).

| Variable | Default | Meaning |
|----------|---------|---------|
| `SECRET_KEY` | none (required) | Flask secret: signs sessions and CSRF tokens, salts the rate-limiter hashes. At least 32 characters. |
| `ENCRYPTION_KEY` | none (required) | Passphrase from which the Fernet key is derived. At least 16 characters. Never change it on an existing database. |
| `ENCRYPTION_SALT` | none (required) | PBKDF2 salt for the key above. At least 16 characters. Never change it on an existing database. |
| `ENCRYPTION_ITERATIONS` | `100000` | PBKDF2 iterations. The default keeps old data readable; use `600000` on a new, empty database. Changing it later makes existing encrypted data unreadable. |
| `DATABASE_URL` | `sqlite:///blog.db` | SQLAlchemy database URI (relative SQLite paths land in `instance/`). |
| `SESSION_COOKIE_SECURE` | `true` | Send cookies only over secure connections. Set `false` for local development over plain HTTP, otherwise you cannot log in. |
| `SESSION_COOKIE_NAME` | `__Host-sid` (or `sid` when not secure) | Session cookie name. |
| `MAX_CONTENT_LENGTH` | `12582912` (12 MiB) | Maximum size of a request body. |
| `MAX_UPLOAD_BYTES` | `10485760` (10 MiB) | Maximum size of one uploaded file. |
| `SECURITY_STATE_DB` | `instance/security_state.db` | SQLite file of the persistent rate limiter (hashed keys only). |
| `ONION_ADDRESS` | empty | v3 onion address (`<56 chars>.onion`). When set, clearnet responses carry an `Onion-Location` header. An invalid value stops the app. |
| `TRUSTED_PROXY_COUNT` | `0` | Number of trusted reverse proxies in front of the app (enables `X-Forwarded-*` handling). Leave `0` when the app is exposed directly, or clients could spoof their address and bypass rate limits. |
| `TRUST_PROXY` | unset | Older syntax: `true` means `TRUSTED_PROXY_COUNT=1`. |
| `FORCE_HSTS` | `false` | Send HSTS even when Flask does not see HTTPS (TLS terminated upstream). Do not use on an onion service. |
| `LOG_CLIENT_IP` | `false` | Keep client IP addresses in the logs. Debugging only. |
| `MOBILE_API_ENABLED` | `true` | `false` disables `/api/admin/mobile/*` (all routes return 404). |
| `TEMPLATE_AUTO_RELOAD` | `false` | Development: reload templates without restarting. |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Address of the development server started by `python wsgi.py`. |
| `FLASK_DEBUG` | `false` | Development server debug mode. Never on a reachable host: the Werkzeug debugger allows code execution. |

Read by the scripts, from the same `.env`:

| Variable | Default | Used by | Meaning |
|----------|---------|---------|---------|
| `UPDATE_RESTART_CMD` | empty | `update.sh`, `auto-update.sh` | Command run after a successful update, e.g. `sudo systemctl restart blog`. |
| `BACKUP_PASSPHRASE` | none (required for backups) | `backup.sh` | Backup encryption passphrase, at least 16 characters. Keep a copy off the server. |
| `BACKUP_KEEP` | `14` | `backup.sh` | Number of local backups kept. |
| `BACKUP_REMOTE` | empty | `backup.sh` | Optional `rsync` target (`user@host:/path/`) for an off-site copy. |

The former Telegram bridge was removed; `TELEGRAM_*` variables are ignored.

## Deployment

The development server (`python wsgi.py`) is not for production. In
production the app runs under gunicorn, bound to `127.0.0.1`, behind a reverse
proxy and/or Tor.

### As a Tor onion service (scripted)

For Debian/Ubuntu, `deploy/deploy-onion.sh` installs what is missing (Python,
Tor, ufw, fail2ban, unattended-upgrades), creates a dedicated system user,
generates the secrets, sets up the onion service and a hardened systemd unit
listening on `127.0.0.1` only, closes inbound traffic in the firewall, creates
an admin account with a random password, and runs leak checks at the end.

```bash
bash deploy/package.sh                        # clean archive of the code only
bash deploy/package.sh 192.168.1.42           # ... and print the scp commands
# then, on the server:
sudo bash deploy/deploy-onion.sh --dry-run    # print every action, change nothing
sudo bash deploy/deploy-onion.sh
sudo bash deploy/harden-tor.sh --status       # optional: obfs4 bridges, vanguards
```

Details, the list of checks, and what the script does not do (disk and swap
encryption, onion key backup) are in [deploy/README.md](deploy/README.md).

### Classic setup (HTTPS, optional onion mirror)

Ready-to-adapt files in `deploy/`:

| File | Purpose |
|------|---------|
| `blog.service` | systemd unit: dedicated unprivileged user, sandboxing, `gunicorn --workers 1 --threads 32` on `127.0.0.1:8000` |
| `Caddyfile` | reverse proxy with automatic HTTPS and access logs discarded, plus a local `127.0.0.1:8080` entry point for Tor |
| `nginx.conf` | alternative reverse proxy (certbot certificates, `access_log off`, WebSocket location) |
| `torrc.example` | onion service pointing at the reverse proxy on `127.0.0.1:8080`; put the generated hostname in `ONION_ADDRESS` |

Production `.env`: keep `SESSION_COOKIE_SECURE=true`, set
`TRUSTED_PROXY_COUNT=1` behind the reverse proxy, set
`ENCRYPTION_ITERATIONS=600000` on a new install, and enable 2FA on every admin
account. Keep a single gunicorn worker: SSE streams and Socket.IO rooms live
in the process.

## Updates and backups

```bash
./update.sh                          # update now (interactive)
./auto-update.sh enable weekly       # daily | weekly | monthly | "<cron expression>"
./auto-update.sh status
./auto-update.sh disable
./backup.sh run                      # encrypted backup: databases + uploads + .env
./backup.sh enable daily             # daily | weekly | "<cron expression>"
./backup.sh restore <file> <dir>     # decrypt into a NEW, empty folder
```

`update.sh`:

1. backs up `instance/`, `uploads/` and any `*.db` into `backups/`;
2. pulls the code with `git pull --ff-only` (aborts if there are local code
   changes);
3. upgrades dependencies from `requirements.txt`;
4. runs `flask db upgrade`;
5. checks that the app imports, and runs the test suite when pytest is
   installed;
6. encrypts any legacy plaintext messages and uploads (`flask encrypt-legacy`);
7. scans dependencies with `pip-audit`;
8. restarts the app with `UPDATE_RESTART_CMD` when set.

If steps 2 to 5 fail, code and dependencies are rolled back. It never modifies
`.env` and never deletes data. Automatic updates are off until you enable
them; they run `./update.sh --auto` from cron, do nothing when there is no new
commit, and log to `logs/update.log`.

`backup.sh` encrypts with gpg (AES-256) when available, otherwise openssl
AES-256-CBC with PBKDF2. Restoring never overwrites the live data.

## Mobile admin API

| Method and path | Purpose |
|-----------------|---------|
| `GET /api/admin/mobile/ping` | test admin authentication |
| `GET /api/admin/mobile/conversations` | users and last message per conversation |
| `GET /api/admin/mobile/conversations/<user_id>/messages?limit=50` | conversation history |
| `POST /api/admin/mobile/conversations/<user_id>/messages` | reply to a user |
| `GET /api/admin/mobile/stream` | real-time event stream (Server-Sent Events) |

Authentication is HTTP Basic with an admin account. If the account has 2FA,
the current code must be sent in the `X-TOTP-Code` header (otherwise 401).
Repeated failures lock the username and the client out for 15 minutes (429).
Set `MOBILE_API_ENABLED=false` to disable it entirely (404). Use it only over
HTTPS or the onion service.

```bash
curl -u admin:your_password -H "X-TOTP-Code: 123456" \
  https://blog.example.org/api/admin/mobile/conversations
```

## Security notes

- Strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`,
  cross-origin isolation headers, generic `Server` header.
- HSTS is sent over HTTPS, when `SESSION_COOKIE_SECURE` is on, or when
  `FORCE_HSTS=true`.
- CSRF tokens on every form, logout included; tokens expire after 4 hours.
- User HTML is escaped or sanitised; uploads are type-checked (SVG, HTML and
  XML refused), size and pixel limited, served only to authorised users.
- Pages for logged-in users are sent with `Cache-Control: no-store`.
- Security events (admin logins, failed admin logins, 2FA changes, role
  changes, deletions) are written to the application log only.

See [SECURITY.md](SECURITY.md) for the security changelog. **To report a
vulnerability, open a private security advisory on GitHub** (Security tab of
the repository) rather than a public issue.

## Tests and CI

```bash
pip install -r requirements-dev.txt
pytest tests                          # security regression tests
pip-audit -r requirements.txt         # known CVEs in dependencies
bandit -r app create_admin.py wsgi.py -q
```

The tests set up their own throwaway database and secrets; no `.env` is
needed. GitHub Actions ([.github/workflows/security.yml](.github/workflows/security.yml))
runs on every push to `main`, every pull request and every Monday:

- `pytest -q tests/` on Python 3.12;
- `pip-audit` on `requirements.txt`;
- `bandit` static analysis;
- a template check that fails on `<script>`, `<style>`, inline event handlers,
  `javascript:` URLs, or external `src`/`href` without `rel="noreferrer"`.

Dependabot opens grouped pull requests for Python dependencies (weekly) and
GitHub Actions (monthly).

## Project layout

```
app/
  __init__.py      app setup, configuration, extensions, template filters
  routes.py        web routes, security headers, SocketIO handlers, moderation, site texts
  services.py      shared helpers: auth, TOTP, uploads, chat, data export, deletion
  mobile_api.py    mobile admin REST API + SSE
  cli.py           maintenance command (flask encrypt-legacy)
  models.py        database models
  forms.py         WTForms classes (anti-spam, validators)
  site_text.py     bilingual copy, admin-editable
  image_safety.py  perceptual hashing, upload block list, quarantine
  encryption.py    Fernet encryption at rest
  utils.py         BBCode, sanitisers, image pipeline, roles, persistent rate limiter
  static/css/      style.css (Small Hours theme), icons.css, admin.css, pages/*.css
  templates/       Jinja2 templates (no JavaScript, no <style>)
migrations/        Alembic migrations (flask db upgrade)
tests/             security regression tests
deploy/            onion deployment script, Tor hardening, systemd, Caddy, nginx, torrc
docs/              ANONYMAT.md (privacy audit), screenshots/
archive/telegram/  removed Telegram bridge, kept read-only
tools/             icon sprite builder
create_admin.py    interactive admin creation
wsgi.py            WSGI entry point (gunicorn wsgi:application)
update.sh  auto-update.sh  backup.sh
```

## Licence

MIT, see [LICENSE](LICENSE).
