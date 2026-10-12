# depressedyoungmanblog

🇬🇧 English · [🇫🇷 Français](README.fr.md)

A personal blog that keeps its readers anonymous. Flask, SQLite, no JavaScript
required, no third-party requests, built to run as a Tor onion service.

> **Vibe coded.** This project was built with heavy help from AI coding tools.
> It has been reviewed and is covered by security regression tests, but read the
> code before trusting it with anything sensitive, and report anything odd.

> **Security updates:** dependencies are pinned past their known CVEs and the
> site runs with **zero JavaScript and zero third-party requests**. Update with
> `./update.sh`, or turn on automatic updates (`./auto-update.sh enable weekly`).
> Details in [SECURITY.md](SECURITY.md).

## What it does

- **Blog** — posts in BBCode (or basic HTML), drafts, scheduled publishing,
  revisions, categories and tags, search, RSS feed (`/feed.xml`)
- **Comments** — nested, BBCode, parsed server-side so they work without JavaScript
- **Encrypted chat** with the site owner — Fernet at rest (messages **and**
  attachments), real-time over WebSocket
- **Bilingual** — every fixed text in English and French, switchable, and editable
  from the admin panel without touching code
- **Moderation** — flag an image and it is fingerprinted, blocked for good, and its
  sender banned; re-encoded copies are caught too
- **2FA** — TOTP per account, with one-time recovery codes
- **Account security page** — change password, log out everywhere, download my
  data, delete my account
- **Mobile admin API** — Basic Auth + `X-TOTP-Code`, SSE event stream
- **No-JS anti-spam** — honeypot + minimum form time, no captcha
- **Gamification** — XP, levels, badges
- **Safe updates** — `./update.sh` (backup, update, health check, automatic
  rollback), optional scheduled updates, encrypted backups

## What it deliberately does not do

- **No JavaScript.** Every page works with JavaScript disabled (the CSP sets
  `script-src 'none'`), so it works in Tor Browser at the "Safest" level.
- **No third-party requests.** No CDN, no web fonts, no analytics, no embedded
  widgets; external images are shown as links, never loaded. A reader's IP
  address never reaches anyone but you. The type falls back to system faces on
  purpose.
- **No Telegram bridge.** It used to forward the *decrypted* content of users'
  messages to Telegram's servers. It was removed and archived read-only in
  `archive/telegram/`; security alerts go to the application log only.
- **No IP addresses in the logs.** They are scrubbed before anything is written.
  The persistent rate limiter stores only keyed hashes (HMAC of the address,
  never the address itself).
- **No tracking of any kind.** No view counters tied to a person, no cookies
  beyond the session.

## Honest limits

Messages are **encrypted at rest**, not end to end. The key lives on the server
next to the database. That protects against the theft of `blog.db` alone — not
against someone with access to the server, and not against a legal demand. Say
"encrypted at rest" to your readers, not "encrypted".

## Running it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then fill in the three required secrets
python -c "import secrets; print(secrets.token_urlsafe(48))"   # ×3

flask db upgrade
python create_admin.py        # first time only
python wsgi.py                # http://127.0.0.1:5000
```

The app refuses to start with missing or example secrets. **Back up
`ENCRYPTION_KEY` and `ENCRYPTION_SALT`**: without them the chat history can never
be decrypted again.

`SESSION_COOKIE_SECURE` defaults to **true**. For development over plain HTTP,
and for an `.onion` served over plain HTTP, set `SESSION_COOKIE_SECURE=false` in
your `.env` (otherwise you cannot log in). `TEMPLATE_AUTO_RELOAD=true` saves
restarts.

## Deploying it

As an onion service (installs what is missing, generates the secrets, creates
the onion service, hardens the systemd unit, closes the firewall, checks that
nothing leaks to the clearnet):

```bash
bash deploy/package.sh 192.168.1.42           # clean archive + the scp commands
# then, on the server:
sudo bash deploy/deploy-onion.sh --dry-run    # see what it will do
sudo bash deploy/deploy-onion.sh
```

See [deploy/README.md](deploy/README.md). Ready-to-use files for a classic
setup are also in `deploy/`:

| File | Purpose |
|------|---------|
| `blog.service` | systemd unit: dedicated unprivileged user, sandboxing, gunicorn on 127.0.0.1 |
| `Caddyfile` | reverse proxy with automatic HTTPS, no access logs |
| `nginx.conf` | alternative reverse proxy (with certbot) |
| `torrc.example` | onion service (then set `ONION_ADDRESS` in `.env`) |

In `.env`: `SESSION_COOKIE_SECURE=true` (HTTPS) and `TRUSTED_PROXY_COUNT=1`
(behind the reverse proxy). Enable 2FA on every admin account.

## Updates and backups

```bash
./update.sh                          # update now
./auto-update.sh enable weekly       # automatic updates: daily | weekly | monthly | "<cron>"
./auto-update.sh status
./backup.sh run                      # encrypted backup of databases + uploads + .env
./backup.sh restore <file> <dir>     # decrypt into a NEW folder (never overwrites live data)
```

`update.sh` backs up the database and uploads, pulls the code (fast-forward
only), upgrades the dependencies, applies migrations, checks the app starts (and
runs the tests when pytest is installed) and **rolls back automatically** if
anything fails. It never touches `.env` and never deletes data. Set
`BACKUP_PASSPHRASE` in `.env` and keep a copy of it outside the server.

## Writing posts

Posts, comments and replies use BBCode: see `/editor_help` on your blog.
External images (`[img]https://...[/img]`) are shown as links and never loaded,
so readers' IP addresses are never sent to other sites. Upload images to the
blog to embed them.

## Mobile admin API

- `GET /api/admin/mobile/ping` — test admin authentication
- `GET /api/admin/mobile/conversations` — users and last message per conversation
- `GET /api/admin/mobile/conversations/<user_id>/messages?limit=50` — history
- `POST /api/admin/mobile/conversations/<user_id>/messages` — reply to a user
- `GET /api/admin/mobile/stream` — real-time event stream (SSE)

HTTP Basic Auth with an admin account; if the account has 2FA, also send the
current code in the `X-TOTP-Code` header. Repeated failures lock the account and
the client out (HTTP 429). Set `MOBILE_API_ENABLED=false` to turn it off (404).

```bash
curl -u admin:your_password -H "X-TOTP-Code: 123456" \
  https://blog.example.org/api/admin/mobile/conversations
```

## Layout

```
app/
  __init__.py      app setup, extensions, template filters
  routes.py        web routes, security headers, SocketIO handlers
  services.py      shared helpers (auth, TOTP, uploads, chat, deletion cascades)
  mobile_api.py    mobile admin REST API + SSE
  cli.py           maintenance commands (flask encrypt-legacy)
  models.py        database models
  forms.py         WTForms classes (anti-spam, validators)
  site_text.py     bilingual copy, admin-editable
  image_safety.py  perceptual hashing + upload block list
  encryption.py    Fernet message encryption
  utils.py         BBCode, sanitizers, image pipeline, roles, persistent rate limiter
  static/css/      style.css (Small Hours theme), icons.css, admin.css, pages/*.css
  templates/       Jinja2 templates (no JavaScript, no <style>)
deploy/            onion + classic deployment files
archive/telegram/  removed Telegram bridge, kept read-only
docs/ANONYMAT.md  privacy audit: what was found, fixed, and still open
tests/             security regression tests
update.sh auto-update.sh backup.sh
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q tests/
pip-audit -r requirements.txt
bandit -r app create_admin.py wsgi.py -q
```

The same checks run on GitHub Actions for every push and every Monday, and
Dependabot opens pull requests for dependency updates.

## Security

- Passwords hashed with bcrypt; TOTP 2FA (brute-force and replay protected) + recovery codes
- Password change, role change and "log out everywhere" invalidate other sessions
- CSRF protection (logout included), strict CSP (`script-src 'none'`, `style-src 'self'`), HSTS over HTTPS
- All user HTML escaped and sanitized (`nh3`); uploads access controlled, metadata stripped, encrypted at rest
- Chat messages encrypted at rest, private per user; GDPR-style export and self-deletion
- Persistent rate limiting with hashed keys (login, 2FA, API, comments, chat)
- Encrypted backups, safe updates with rollback

See [SECURITY.md](SECURITY.md) for the changelog and how to report a vulnerability.

## Licence

See [LICENSE](LICENSE).
