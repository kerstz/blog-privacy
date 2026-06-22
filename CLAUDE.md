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
- **Telegram Bot API** for admin bridge (manage from Telegram)
- **Flask-WTF** for CSRF + forms

## Project structure
```
app/
  __init__.py       - Flask app, extensions init
  models.py         - 13 database models (Post, Comment, User, Message, Like, Notification, Badge, Banner, StaticPage, Revision, Donor, ContactMessage)
  routes.py         - All routes (~3400 lines: web routes + Telegram bot + mobile admin API + SSE)
  forms.py          - 12 WTForms classes
  utils.py          - BBCode parser, image pipeline, role system, rate limiter
  encryption.py     - Fernet-based message encryption
  chat.py           - SocketIO message handler
  static/css/       - style.css (dark theme) + icons.css
  static/ui-demos/  - Reference UI demos (39+ HTML files)
  templates/        - 42 Jinja2 templates
config.py           - Flask configuration class
wsgi.py             - WSGI entry point
create_admin.py     - Interactive admin creation
migrations/         - Alembic migrations
uploads/            - User uploads
```

## Key features
- Blog with CKEditor, scheduled posts, drafts, revisions
- Nested comments with BBCode support
- Like/unlike system for posts and comments
- Gamification: XP, levels, badges with auto-awards
- Encrypted user-to-admin chat (Fernet + SocketIO real-time)
- TOTP 2FA (enable/disable per user)
- Telegram admin bot (manage posts/users/comments, reply to chats)
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
- Telegram integration is optional (env vars)
- Templates extend layout.html or admin_layout.html

## Environment variables
- `SECRET_KEY` - Flask secret key
- `DATABASE_URL` - SQLAlchemy URI (default: sqlite:///blog.db)
- `ENCRYPTION_KEY` / `ENCRYPTION_SALT` - Fernet encryption
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_ADMIN_CHAT_ID` / `TELEGRAM_ADMIN_USER_ID` - Telegram bot
- `TELEGRAM_ADMIN_PIN` / `TELEGRAM_ADMIN_SESSION_TTL` / `TELEGRAM_AUDIT_CHAT_ID` - Telegram security
- `SESSION_COOKIE_SECURE` / `MAX_CONTENT_LENGTH` / `MAX_UPLOAD_BYTES`
