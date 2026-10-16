from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from datetime import timedelta
from markupsafe import Markup, escape
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import os
import logging
import ipaddress

from dotenv import load_dotenv

# Charge les variables d'environnement depuis un fichier .env local (jamais commité)
load_dotenv()

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
        "SECRET_KEY trop faible (valeur d'exemple ou < 32 caracteres). Generez-en une avec : "
        "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
# Cookie securise par defaut : il faut poser SESSION_COOKIE_SECURE=false
# explicitement pour developper en HTTP, plutot que d'oublier de l'activer en
# production et d'envoyer le cookie de session en clair.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() in ('1', 'true', 'yes')
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Strict : le cookie n'accompagne aucune requete initiee par un autre site, y
# compris un simple lien entrant. Un visiteur arrivant depuis un lien externe
# apparait deconnecte jusqu'a sa premiere navigation interne.
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# Nom de cookie neutre : "session" annonce Flask a qui inspecte les en-tetes.
app.config['SESSION_COOKIE_NAME'] = os.environ.get('SESSION_COOKIE_NAME', '__Host-sid') \
    if app.config['SESSION_COOKIE_SECURE'] else os.environ.get('SESSION_COOKIE_NAME', 'sid')
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Strict'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
# CSRF tokens expire with the session instead of living forever
app.config['WTF_CSRF_TIME_LIMIT'] = 4 * 3600
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 12 * 1024 * 1024))
# Empeche l'enregistrement des identifiants de session dans les journaux via
# l'URL et limite la duree de vie des reponses en cache navigateur.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(hours=12)
# En developpement, recharger les gabarits a chaque requete. Sans cela, toute
# modification d'un <style> inline ou d'un fragment Jinja exige un redemarrage
# du serveur — les fichiers CSS, eux, sont deja invalides par static_v().
if os.environ.get('TEMPLATE_AUTO_RELOAD', '').lower() in ('1', 'true', 'yes'):
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.jinja_env.auto_reload = True

# Derriere un reverse proxy (nginx, Caddy, Tor onion service...), `request.remote_addr`
# vaut sinon 127.0.0.1 pour tout le monde : le rate limiting s'appliquerait
# globalement au lieu de par visiteur. TRUSTED_PROXY_COUNT = nombre de proxys de
# confiance devant l'application (TRUST_PROXY=true vaut 1, ancienne syntaxe).
# Ne jamais l'activer si l'application est exposee directement : un client
# pourrait forger X-Forwarded-For.
_proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '0') or 0)
if _proxy_count <= 0 and os.environ.get('TRUST_PROXY', '').lower() in ('1', 'true', 'yes'):
    _proxy_count = 1
app.config['TRUSTED_PROXY_COUNT'] = max(_proxy_count, 0)
if _proxy_count > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_count, x_proto=_proxy_count, x_host=_proxy_count)


# Journalisation : par defaut le serveur de developpement Werkzeug ecrit une
# ligne par requete contenant l'adresse IP du visiteur. Sur un blog dont la
# raison d'etre est l'anonymat, ce journal est la fuite la plus banale.
class _StripClientAddressFilter(logging.Filter):
    # Candidats larges ; chacun est ensuite valide par le module `ipaddress`.
    # Sans cette validation, le motif IPv6 avale les horodatages : `11:14:32`
    # a exactement la forme de trois groupes separes par des deux-points.
    _CANDIDATE = re.compile(
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
        r'|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'
    )

    @classmethod
    def _mask(cls, match):
        token = match.group(0)
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            return token  # ce n'etait pas une adresse (horodatage, version...)
        # La boucle locale n'identifie personne et reste utile en developpement.
        if addr.is_loopback:
            return token
        return '[ip]'

    def filter(self, record):
        try:
            # Interpoler d'abord (`record.args` disparait ensuite), sinon les
            # `%s` restants provoquent une erreur de formatage.
            rendered = record.getMessage()
        except Exception:
            return True
        record.msg = self._CANDIDATE.sub(self._mask, rendered)
        record.args = ()
        return True


if os.environ.get('LOG_CLIENT_IP', '').lower() not in ('1', 'true', 'yes'):
    for _logger_name in ('werkzeug',):
        logging.getLogger(_logger_name).addFilter(_StripClientAddressFilter())
    app.logger.addFilter(_StripClientAddressFilter())


# Initialisation des extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# 'basic' (not 'strong'): Tor / mobile users change IP often and must not be
# logged out on every circuit change.
login_manager.session_protection = 'basic'


# Importez routes, models et client après l'initialisation
from app import routes, models, cli  # noqa: E402,F401  (registers routes + CLI commands)

# Fonction de chargement de l'utilisateur pour Flask-Login
@login_manager.user_loader
def load_user(user_id):
    # "<id>:<session_version>" : une session creee avant un changement de mot de
    # passe ou un "deconnexion partout" ne correspond plus et est rejetee. Un
    # ancien cookie ("5", sans version) vaut version 0.
    try:
        raw_id, _, raw_version = str(user_id).partition(':')
        user = db.session.get(models.User, int(raw_id))
        version = int(raw_version or 0)
    except (TypeError, ValueError):
        return None
    if user is None or (user.session_version or 0) != version:
        return None
    return user

# Textes du site et langue courante, disponibles dans tous les gabarits.
# `t()` rend du texte simple (echappe par Jinja), `t_rich()` rend un bloc long
# via le parseur BBCode.
@app.context_processor
def inject_site_text():
    from app.site_text import (LANGUAGES, current_language, format_date,
                               get_text, get_rich_text)
    return dict(
        t=get_text,
        t_rich=get_rich_text,
        fmt_date=format_date,
        current_language=current_language,
        LANGUAGES=LANGUAGES,
    )


@app.url_defaults
def _keep_language_in_urls(endpoint, values):
    """Conserve ?lang= sur les liens internes.

    Sans cela, un visiteur qui bascule en francais repasse en anglais des le
    premier lien suivi, tant que la session n'a pas ete ecrite.
    """
    from flask import g, request
    if 'lang' in values or not request:
        return
    chosen = request.args.get('lang')
    if chosen and getattr(g, 'lang', None) == chosen:
        values['lang'] = chosen


# Injecter des modèles dans le contexte global de Jinja2 pour les rendre disponibles dans toutes les templates
@app.context_processor
def inject_models():
    from app.models import Banner
    return dict(Banner=Banner)

# Les fichiers statiques sont servis avec un cache long (SEND_FILE_MAX_AGE_DEFAULT).
# Sans empreinte dans l'URL, une modification de style.css n'atteint jamais un
# lecteur deja venu. `static_v()` ajoute la date de modification du fichier :
# l'URL change des que le fichier change, et seulement a ce moment-la.
@app.template_global()
def static_v(filename):
    from flask import url_for
    try:
        stamp = int(os.stat(os.path.join(app.static_folder, filename)).st_mtime)
    except OSError:
        return url_for('static', filename=filename)
    return url_for('static', filename=filename, v=stamp)


# Définition du filtre `urlize` pour transformer les URLs en liens hypertexte
@app.template_filter('urlize')
def urlize_filter(s):
    # Echapper AVANT de generer le HTML : `s` peut contenir du contenu utilisateur.
    return Markup(re.sub(r'(?<!\w)(/post/\d+)', r'<a href="\1">\1</a>', str(escape(s or ''))))  # nosec B704

@app.template_filter('bbcode')
def bbcode_filter(s):
    # parse_bbcode echappe le texte AVANT de generer le HTML.
    from app.utils import parse_bbcode
    return Markup(parse_bbcode(s or ''))  # nosec B704


@app.template_filter('comment_html')
def comment_html_filter(comment):
    """HTML sur d'un commentaire : objet Comment (BBCode ou ancien HTML assaini)
    ou simple chaine (traitee comme du BBCode)."""
    from app.utils import parse_bbcode, sanitize_legacy_html
    if isinstance(comment, str) or comment is None:
        return Markup(parse_bbcode(comment or ''))  # nosec B704
    if comment.content_format == 'bbcode':
        return Markup(parse_bbcode(comment.content or ''))  # nosec B704
    return Markup(sanitize_legacy_html(comment.content or ''))  # nosec B704


@app.template_filter('excerpt')
def excerpt_filter(text, length=180):
    """Plain-text preview of a post (BBCode/HTML rendered, then stripped)."""
    from app.utils import render_rich_html
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
    return Markup(render_rich_html(s))  # nosec B704


if __name__ == '__main__':
    app.run()
