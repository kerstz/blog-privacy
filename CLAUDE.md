# blog-privacy

Full-featured privacy-focused blog platform built with Flask. Brand name:
depressedyoungman. No JavaScript, no third-party requests, Tor friendly.

## Stack
- **Flask** + SQLAlchemy + Flask-Migrate + SQLite
- **Flask-Login** + **Flask-Bcrypt** for auth
- Server-sent events only (no WebSocket / Socket.IO); Python 3.12+
- **Fernet** (cryptography) for message and upload encryption at rest
- **pyotp** + **qrcode** for TOTP 2FA (+ recovery codes)
- **Pillow** for image re-encoding / metadata stripping, **nh3** for HTML sanitizing
- **Flask-WTF** for CSRF + forms

## Project structure
```
app/
  __init__.py       - Flask app, extensions init, template filters
  models.py         - database models (Post, Comment, User, Message, Like, Notification, Badge, Banner, StaticPage, Revision, Donor, ContactMessage, Tag, SiteText, SiteTextRevision, BlockedImageHash, BlockedUploadEvent)
  routes.py         - web routes, security headers, moderation, site-text editor
  services.py       - shared helpers: auth (password/TOTP), upload pipeline, chat, deletion cascades, badges
  mobile_api.py     - mobile admin REST API (Basic Auth + X-TOTP-Code) + SSE
  cli.py            - maintenance commands (`flask encrypt-legacy`)
  forms.py          - WTForms classes (AntiSpamMixin, validators)
  utils.py          - BBCode parser, sanitizers, image pipeline, roles, persistent rate limiter
  encryption.py     - Fernet-based message encryption
  site_text.py      - Bilingual site copy (EN/FR), admin-editable
  image_safety.py   - Perceptual hashing + upload block list
  static/css/       - style.css (Small Hours theme) + icons.css + admin.css + pages/*.css (one per page)
  templates/        - Jinja2 templates (NO JavaScript, NO <style>)
wsgi.py             - WSGI entry point
create_admin.py     - Interactive admin creation
migrations/         - Alembic migrations (one linear chain, head e1f2a3b4c5d6)
deploy/             - onion deployment + systemd / Caddy / nginx / torrc examples
tests/              - security regression tests (conftest.py shared setup)
update.sh auto-update.sh backup.sh - safe update, scheduled update, encrypted backups
uploads/            - User uploads (encrypted at rest)
archive/telegram/   - Removed Telegram bridge, kept read-only
```

## Running
```bash
pip install --require-hashes -r requirements.lock   # Python 3.12+; regenerate with uv, see README.md
flask db upgrade                # run migrations
python create_admin.py          # first time
python wsgi.py                  # or gunicorn wsgi:application
pytest -q tests/                # needs requirements-dev.txt
```

## Conventions
- No JavaScript and no `<style>` blocks or inline handlers in templates (CSP
  `script-src 'none'`, `style-src 'self'`): CSS goes in `static/css/pages/<page>.css`,
  included with `{% block extra_css %}`. Confirmations use `<details class="confirm-action">`
- Colors come from the Small Hours tokens (`--night-*`, `--ash*`, `--moon*`, `--ember*`)
- Admin routes use `@admin_required`; templates extend `layout.html` or `admin_layout.html`
- Rate limiting and failure counters are persistent (SQLite, keys hashed with HMAC):
  `hit_rate_limit()` / `@rate_limit` / `record_failure()`; tests reset it with `utils.reset_security_state()`
- Sessions carry `User.session_version` (`get_id()` = "id:version"): bump it with
  `invalidate_other_sessions()` or `user.rotate_session_token()`
- Logout is POST + CSRF
- TOTP secrets are encrypted at rest (`_totp_secret` / `_store_totp_secret`); replay
  protection is `User.totp_last_counter`
- Uploads go through `_store_upload()` (in memory: block-list screening, WebP re-encode,
  then one encrypted `.enc` write; never plaintext on disk) and are served by
  `_send_upload()`; read them with `read_upload_bytes()`
- BBCode from users is rendered with `render_user_bbcode()` (parse_bbcode + nh3)
- Tests never touch the project's `instance/` or `uploads/`: conftest points
  `UPLOAD_DIR`, `QUARANTINE_DIR`, `SECURITY_STATE_DB` and the DB at a temp dir
- Comments: `content_format='bbcode'` = plain text escaped + BBCode; `NULL` = legacy HTML
  sanitized at render. Never use `|safe` on user content (`|comment_html`, `|rich_html`, `|bbcode`)
- UI texts go through `t('key')` and `site_text.DEFAULTS` (EN + FR)
- BBCode is parsed server-side (NoScript friendly)
- Telegram bridge removed; archived read-only in archive/telegram/
- `bandit -r app create_admin.py wsgi.py -q` and `pip-audit -r requirements.lock --require-hashes --disable-pip --strict` must stay clean; edit requirements.in then re-lock
- Threat model: the anonymous Tor visitor is the nominal adversary (no client IP; per-account limits, not per-IP)
- `GET /healthz`: anonymous health probe (`ok`/503), nothing else
- CLI: `flask unlock <user>|--all`, `flask purge-contact --days 90`, `flask purge-messages --days N`, `flask purge-notifications --days 90`, `flask rotate-key [--dry-run]`, `flask maintenance on|off|status`; admin view `/admin/contact`

## Environment variables
- `SECRET_KEY` (>= 32 chars) - Flask secret key
- `DATABASE_URL` - SQLAlchemy URI (default: sqlite:///blog.db)
- `ENCRYPTION_KEY` / `ENCRYPTION_SALT` (>= 16 chars) - Fernet encryption
- `ENCRYPTION_ITERATIONS` - PBKDF2 iterations (default 100000; use 600000 on a fresh install)
- `TRUSTED_PROXY_COUNT` (or legacy `TRUST_PROXY`) / `FORCE_HSTS` / `LOG_CLIENT_IP` - proxy, HSTS and log-scrubbing switches
- `SESSION_COOKIE_SECURE` (default true; false for plain-HTTP dev or http .onion) / `MAX_CONTENT_LENGTH` / `MAX_UPLOAD_BYTES`
- `SECURITY_STATE_DB` - persistent rate limiter file (default instance/security_state.db)
- `ONION_ADDRESS` - adds the Onion-Location header
- `MOBILE_API_ENABLED` - mobile admin API (default false; `/api/admin/mobile/*` returns 404 unless true). Admins must have TOTP and send the code in `X-TOTP-Code`
- `ENCRYPTION_OLD_KEY` / `ENCRYPTION_OLD_SALT` / `ENCRYPTION_OLD_ITERATIONS` - previous key during a rotation (`flask rotate-key`)
- `UPLOAD_DIR` / `QUARANTINE_DIR` / `MAINTENANCE_FLAG` - data locations (defaults: uploads/, instance/quarantine, instance/maintenance.on)
- `PUBLIC_TIME_PRECISION` - `day` (default) or `minute`: dates on public pages and RSS
- `BLOG_ENV_FILE` / `BACKUP_DIR` - backup.sh overrides (deploy-onion.sh layout)
