# blog-privacy

Privacy-focused blog platform built with Flask. No JavaScript, no third-party
requests, Tor friendly. Everything (code, comments, UI, docs) is written in
English; French translations of the docs live in `*.fr.md`.

## Stack
- **Flask** + SQLAlchemy + Flask-Migrate + SQLite
- **Flask-Login** + **Flask-Bcrypt** for auth, **pyotp** + **qrcode** for TOTP 2FA
- **Flask-SocketIO** for real-time events (authenticated, per-user rooms)
- **Fernet** (cryptography) for chat encryption at rest
- **nh3** HTML sanitizer, **Pillow** for metadata stripping / WebP re-encoding
- **Telegram Bot API** admin bridge (optional)
- **Flask-WTF** for CSRF + forms

## Project structure
```
app/
  __init__.py       - Flask app, extensions, template filters (comment_html, rich_html, qr_data_uri)
  models.py         - database models
  routes.py         - web routes + SocketIO handlers + security headers
  services.py       - shared helpers: auth (password/TOTP), uploads, chat, deletion cascades, badges
  telegram_bot.py   - Telegram admin bot (poller thread, commands, PIN lock)
  mobile_api.py     - mobile admin REST API (Basic Auth + X-TOTP-Code, SSE)
  cli.py            - maintenance commands (`flask encrypt-legacy`)
  forms.py          - WTForms classes
  utils.py          - BBCode parser, sanitizers, image pipeline, persistent rate limiter
  encryption.py     - Fernet message encryption
  static/css/       - style.css (Night Desk theme), icons.css, fonts.css, pages/*.css (per-page styles)
  static/fonts/     - self-hosted fonts (SIL OFL)
  templates/        - Jinja2 templates (NO JavaScript)
deploy/             - systemd unit, Caddyfile, nginx.conf, torrc example
docs/               - screenshots, UI demos (not served)
tests/              - security regression tests
update.sh           - safe updater (backup, pull, deps, migrations, health check, rollback)
auto-update.sh      - optional scheduled updates (daily/weekly/monthly/cron)
backup.sh           - encrypted backups + restore
create_admin.py     - interactive admin creation
wsgi.py             - WSGI entry point
```

## Running
```bash
pip install -r requirements.txt
flask db upgrade
python create_admin.py          # first time
python wsgi.py                  # dev; production: deploy/blog.service (gunicorn)
./update.sh                     # safe update
./auto-update.sh enable weekly  # optional automatic updates
./backup.sh run                 # encrypted backup
pytest -q tests/                # security regression tests (requirements-dev.txt)
```

## Conventions
- English only in code, comments, UI strings and main docs; update the `*.fr.md` translations when docs change
- No JavaScript and no `<style>` blocks in templates, no third-party resources (CI enforces it; CSP is `script-src 'none'`, `style-src 'self'`): put CSS in `static/css/pages/`
- Public forms use `AntiSpamMixin` (honeypot `website` field rendered with class `hp-field` + signed `form_ts`)
- Uploaded files are encrypted at rest (`.enc`); read them with `read_upload_bytes()`
- Sensitive account actions re-authenticate (`ReauthForm` + `_reauthenticate()`) and call `security_alert()`
- Sessions carry `User.session_version` (via `get_id()`): bump it with `invalidate_other_sessions()`
- Logout is POST + CSRF
- `bandit -r app -q` must stay clean (annotate reviewed false positives with a reason line + `# nosec <ID>`)
- Never use `|safe` on user/admin HTML: use `|comment_html` (BBCode) or `|rich_html` (posts/pages)
- Uploads go through `_store_upload()` (random name, metadata stripped) and are served by `_send_upload()` (access controlled)
- Real-time events: `_notify_user()` / per-user rooms only, never broadcast
- Rate limiting: `hit_rate_limit()` / `@rate_limit` (persistent SQLite store)
- Admin routes use `@admin_required`
- Keep requirements.txt pinned and CVE-free (`pip-audit -r requirements.txt`); see SECURITY.md
- Telegram integration is optional (env vars)

## Environment variables
See `.env.example` (secrets, production, updates, backups, Telegram).
