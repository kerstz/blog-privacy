from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_socketio import SocketIO
from datetime import timedelta
from markupsafe import Markup, escape
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import os

from dotenv import load_dotenv

# Load environment variables from a local .env file (never committed)
load_dotenv()

# Application setup
app = Flask(__name__)

# Configuration
# SECRET_KEY is mandatory: no predictable default (the repository is public)
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Set it in a .env file or as an environment variable "
        "(see .env.example). No default value is provided."
    )
if SECRET_KEY.lower() in ('change_me', 'changeme', 'secret', 'dev') or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY is too weak (example value or < 32 characters). Generate one with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = '__Host-session' if app.config['SESSION_COOKIE_SECURE'] else 'session'
# "Remember me" cookie hardening (Flask-Login)
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
# CSRF tokens expire with the session instead of living forever
app.config['WTF_CSRF_TIME_LIMIT'] = 4 * 3600
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 12 * 1024 * 1024))

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# 'basic' (not 'strong'): Tor / mobile users change IP often and must not be
# logged out on every circuit change.
login_manager.session_protection = 'basic'
# Same-origin only, bounded message size (python-socketio CVE-2026-48804 class DoS)
socketio = SocketIO(app, cors_allowed_origins=None, max_http_buffer_size=1_000_000)

# Behind a reverse proxy (nginx, Caddy...), set TRUSTED_PROXY_COUNT=1 so that
# request.remote_addr (used for rate limiting) is the real client IP and not
# the proxy's. Never enable it when the app is directly exposed.
_proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '0') or 0)
if _proxy_count > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)


# Import routes and models after the app is initialized
from app import routes, models, cli  # noqa: E402,F401  (registers routes + CLI commands)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    # "<id>:<session_version>": a session created before a password change or
    # a "log out everywhere" no longer matches and is rejected.
    try:
        raw_id, _, raw_version = str(user_id).partition(':')
        user = db.session.get(models.User, int(raw_id))
        version = int(raw_version or 0)
    except (TypeError, ValueError):
        return None
    if user is None or (user.session_version or 0) != version:
        return None
    return user

# Make some models available in every Jinja2 template
@app.context_processor
def inject_models():
    from app.models import Banner
    return dict(Banner=Banner)

# `urlize` filter: turn internal /post/<id> paths into links
@app.template_filter('urlize')
def urlize_filter(s):
    # SECURITY: escape first, then linkify internal post paths only
    # bandit B704: input escaped first
    return Markup(re.sub(r'(?<!\w)(/post/\d+)', r'<a href="\1">\1</a>', str(escape(s or ''))))  # nosec B704


@app.template_filter('comment_html')
def comment_html_filter(s):
    from app.utils import render_comment_html
    # bandit B704: escaped + nh3-sanitized
    return Markup(render_comment_html(s))  # nosec B704


@app.template_filter('excerpt')
def excerpt_filter(text, length=180):
    """Plain-text preview of a post (BBCode/HTML rendered, then stripped)."""
    from app.utils import render_rich_html
    # bandit B704: sanitized, then reduced to plain text
    plain = Markup(render_rich_html(text)).striptags()  # nosec B704
    if len(plain) <= length:
        return plain
    return plain[:length].rsplit(' ', 1)[0] + '…'


@app.template_filter('slug')
def slug_filter(text):
    from app.services import slugify
    return slugify(text)


@app.template_filter('qr_data_uri')
def qr_data_uri_filter(text):
    """QR code as an inline PNG data: URI (generated server-side, no JS, no CDN)."""
    import base64, io, qrcode
    buf = io.BytesIO()
    qrcode.make(str(text or ''), box_size=4, border=2).save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')


@app.template_filter('rich_html')
def rich_html_filter(s):
    from app.utils import render_rich_html
    # bandit B704: nh3-sanitized
    return Markup(render_rich_html(s))  # nosec B704


from app.models import Donor

@app.context_processor
def inject_top_donor():
    top_donor = Donor.query.order_by(Donor.amount.desc()).first()
    return dict(top_donor=top_donor)
