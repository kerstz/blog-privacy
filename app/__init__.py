from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_ckeditor import CKEditor
from flask_socketio import SocketIO
from datetime import timedelta
from markupsafe import Markup, escape
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import os

from dotenv import load_dotenv

# Charge les variables d'environnement depuis un fichier .env local (jamais commité)
load_dotenv()

from flask_socketio import SocketIO
# Initialisation de l'application
app = Flask(__name__)

# Configuration de l'application
# SECRET_KEY est obligatoire : pas de valeur par défaut prévisible (le dépôt est public)
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY manquante. Définissez-la dans un fichier .env ou une variable "
        "d'environnement (voir .env.example). Aucune valeur par défaut n'est fournie."
    )
if SECRET_KEY.lower() in ('change_me', 'changeme', 'secret', 'dev') or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY trop faible (valeur d'exemple ou < 32 caractères). Générez-en une avec : "
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

# Configuration CKEditor
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'

# Initialisation des extensions
ckeditor = CKEditor(app)
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


# Importez routes, models et client après l'initialisation
from app import routes, models, chat

# Fonction de chargement de l'utilisateur pour Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(models.User, int(user_id))
    except (TypeError, ValueError):
        return None

# Injecter des modèles dans le contexte global de Jinja2 pour les rendre disponibles dans toutes les templates
@app.context_processor
def inject_models():
    from app.models import Banner
    return dict(Banner=Banner)

# Définition du filtre `urlize` pour transformer les URLs en liens hypertexte
@app.template_filter('urlize')
def urlize_filter(s):
    # SECURITY: escape first, then linkify internal post paths only
    return Markup(re.sub(r'(?<!\w)(/post/\d+)', r'<a href="\1">\1</a>', str(escape(s or ''))))


@app.template_filter('comment_html')
def comment_html_filter(s):
    from app.utils import render_comment_html
    return Markup(render_comment_html(s))


@app.template_filter('rich_html')
def rich_html_filter(s):
    from app.utils import sanitize_rich_html
    return Markup(sanitize_rich_html(s))


from app.models import Donor

@app.context_processor
def inject_top_donor():
    top_donor = Donor.query.order_by(Donor.amount.desc()).first()
    return dict(top_donor=top_donor)
