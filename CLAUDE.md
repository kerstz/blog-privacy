# blog-privacy

Full-featured privacy-focused blog platform built with Flask.

## Stack
- **Flask** + SQLAlchemy + Flask-Migrate + SQLite
- **Flask-Login** + **Flask-Bcrypt** for auth
- **Flask-SocketIO** for real-time WebSocket messaging
- **Fernet** (cryptography) for message encryption
- **pyotp** + **qrcode** for TOTP 2FA
- **Pillow** + **piexif** for EXIF stripping / image processing
- **Flask-CKEditor** for rich text editing
- **Flask-WTF** for CSRF + forms

## Project structure
```
app/
  __init__.py       - Flask app, extensions init
  models.py         - 16 database models (Post, Comment, User, Message, Like, Notification, Badge, Banner, StaticPage, Revision, Donor, ContactMessage, SiteText, BlockedImageHash, BlockedUploadEvent)
  routes.py         - All routes (~1900 lines: web routes + mobile admin API + SSE)
  forms.py          - 12 WTForms classes
  utils.py          - BBCode parser, image pipeline, role system, rate limiter
  encryption.py     - Fernet-based message encryption
  site_text.py      - Bilingual site copy (EN/FR), admin-editable
  image_safety.py   - Perceptual hashing + upload block list
  chat.py           - SocketIO message handler
  static/css/       - style.css (Small Hours theme) + icons.css + admin.css
  templates/        - 43 Jinja2 templates
wsgi.py             - WSGI entry point
create_admin.py     - Interactive admin creation
migrations/         - Alembic migrations
uploads/            - User uploads
archive/telegram/   - Removed Telegram bridge, kept read-only
```

## Key features
- Blog with CKEditor, scheduled posts, drafts, revisions
- Nested comments with BBCode support
- Like/unlike system for posts and comments
- Gamification: XP, levels, badges with auto-awards
- Encrypted user-to-admin chat (Fernet + SocketIO real-time)
- TOTP 2FA (enable/disable per user)
- Mobile admin REST API (Basic Auth + SSE stream)
- Banners, static pages, donations, contact form
- Privacy: encrypted messages, EXIF stripping, CSRF, bcrypt, rate limiting

## Running
```bash
pip install -r requirements.txt
flask db upgrade                # run migrations
python create_admin.py          # first time
python wsgi.py                  # or gunicorn wsgi:application
```

## Conventions
- Routes are all in one large routes.py file
- Admin routes use @admin_required decorator
- Rate limiting is in-memory (per IP/user)
- BBCode is parsed server-side (NoScript friendly)
- Telegram bridge removed; archived read-only in archive/telegram/
- Templates extend layout.html or admin_layout.html

## Environment variables
- `SECRET_KEY` - Flask secret key
- `DATABASE_URL` - SQLAlchemy URI (default: sqlite:///blog.db)
- `ENCRYPTION_KEY` / `ENCRYPTION_SALT` - Fernet encryption
- `ENCRYPTION_ITERATIONS` - PBKDF2 iterations (default 100000; use 600000 on a fresh install)
- `TRUST_PROXY` / `FORCE_HSTS` / `LOG_CLIENT_IP` - proxy, HSTS and log-scrubbing switches
- `SESSION_COOKIE_SECURE` / `MAX_CONTENT_LENGTH` / `MAX_UPLOAD_BYTES`
- `MOBILE_API_ENABLED` - mobile admin API (default true; `false` makes `/api/admin/mobile/*` return 404). Accounts with TOTP 2FA are refused by the API
