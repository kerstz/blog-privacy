# app/utils.py
from app import db
from functools import wraps
from flask import redirect, url_for, flash, request
from flask_login import current_user
from app.models import Post
from datetime import datetime
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
import time
import re
import hashlib
import html as _html
import threading
from html.parser import HTMLParser
from urllib.parse import urlparse
from PIL import Image, ExifTags
from markupsafe import escape
import os


# -----------------------------
# BBCode parsing (server-side, NoScript friendly)
# -----------------------------

_BB_TAGS = [
    (re.compile(r"\[b\](.*?)\[/b\]", re.IGNORECASE | re.DOTALL), r"<strong>\1</strong>"),
    (re.compile(r"\[i\](.*?)\[/i\]", re.IGNORECASE | re.DOTALL), r"<em>\1</em>"),
    (re.compile(r"\[u\](.*?)\[/u\]", re.IGNORECASE | re.DOTALL), r"<u>\1</u>"),
    (re.compile(r"\[s\](.*?)\[/s\]", re.IGNORECASE | re.DOTALL), r"<s>\1</s>"),
    (re.compile(r"\[quote\](.*?)\[/quote\]", re.IGNORECASE | re.DOTALL), r"<blockquote>\1</blockquote>"),
    (re.compile(r"\[code\](.*?)\[/code\]", re.IGNORECASE | re.DOTALL), r"<pre><code>\1</code></pre>"),
]

def _sanitize_url(url: str, allow_data: bool = False) -> str:
    url = (url or '').strip()
    if not url:
        return '#'
    # allow only http/https ; data:image only for [img] (allow_data), never for links
    lowered = url.lower()
    if not (lowered.startswith('http://') or lowered.startswith('https://')
            or (allow_data and lowered.startswith('data:image'))):
        return '#'
    return url

def parse_bbcode(text: str) -> str:
    """Convertit du BBCode en HTML.

    Le texte brut est echappe AVANT toute conversion : sans cela, un commentaire
    contenant `<script>` etait stocke tel quel puis rendu avec `| safe` — une
    XSS stockee declenchee chez tous les lecteurs de l'article.
    """
    if not text:
        return ''
    html = escape(text).__str__()
    # [url=...]text[/url] and [url]link[/url]
    html = re.sub(r"\[url=(.+?)\](.*?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener noreferrer\">{m.group(2)}</a>", html, flags=re.IGNORECASE)
    html = re.sub(r"\[url\](.+?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener noreferrer\">{m.group(1)}</a>", html, flags=re.IGNORECASE)
    # [img]...[/img] and [img=width,height]...[/img]
    def _img_simple(m):
        src = _sanitize_url(m.group(1), allow_data=True)
        return f"<img src=\"{src}\" alt=\"image\" style=\"max-width:100%;height:auto;\">"
    html = re.sub(r"\[img\](.+?)\[/img\]", _img_simple, html, flags=re.IGNORECASE)
    def _img_sized(m):
        dims = m.group(1).split(',')
        try:
            w = int(dims[0]) if dims[0] else 0
            h = int(dims[1]) if len(dims) > 1 else 0
        except Exception:
            w, h = 0, 0
        src = _sanitize_url(m.group(2), allow_data=True)
        style = []
        if w > 0:
            style.append(f"max-width:{w}px")
        if h > 0:
            style.append(f"max-height:{h}px")
        style.append("height:auto")
        return f"<img src=\"{src}\" alt=\"image\" style=\"{' ; '.join(style)}\">"
    html = re.sub(r"\[img=(.*?)\](.+?)\[/img\]", _img_sized, html, flags=re.IGNORECASE)
    # lists [list] [*]item
    def _list_repl(m):
        items = re.findall(r"\[\*\](.+)", m.group(1))
        li = ''.join([f"<li>{it.strip()}</li>" for it in items])
        return f"<ul>{li}</ul>"
    html = re.sub(r"\[list\](.*?)\[/list\]", _list_repl, html, flags=re.IGNORECASE | re.DOTALL)
    # colors and sizes
    html = re.sub(r"\[color=(#[0-9a-fA-F]{3,6}|[a-zA-Z]+)\](.*?)\[/color\]", r"<span style=\"color:\1\">\2</span>", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"\[size=(\d{1,3})\](.*?)\[/size\]", r"<span style=\"font-size:\1px\">\2</span>", html, flags=re.IGNORECASE | re.DOTALL)
    # basic tags
    for pattern, repl in _BB_TAGS:
        html = pattern.sub(repl, html)
    return html


# -----------------------------
# Anciens commentaires : HTML stocke tel quel
# -----------------------------
# Avant le correctif, `reply_to_comment` et `edit_comment` stockaient le texte
# brut du formulaire et le gabarit l'affichait avec `| safe` (XSS stockee).
# Les anciennes lignes ne sont PAS reecrites : elles sont assainies a
# l'affichage par cette liste blanche, calquee sur ce que produit parse_bbcode.

_LEGACY_ALLOWED_TAGS = {'strong', 'em', 'u', 's', 'blockquote', 'pre', 'code',
                        'ul', 'li', 'a', 'img', 'span', 'br', 'p'}
_LEGACY_VOID_TAGS = {'br', 'img'}
# Contenu supprime avec la balise (et non simplement affiche en texte).
_LEGACY_DROP_CONTENT = {'script', 'style', 'iframe', 'object', 'embed', 'noscript',
                        'template', 'svg', 'math', 'head', 'title', 'textarea'}
_LEGACY_STYLE_RE = re.compile(
    r'^(?:\s*(?:max-width:\d{1,4}px|max-height:\d{1,4}px|height:auto|'
    r'color:(?:#[0-9a-fA-F]{3,6}|[a-zA-Z]+)|font-size:\d{1,3}px)\s*(?:;|$))+$')


class _LegacyHTMLSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.open_tags = []
        self.drop_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in _LEGACY_DROP_CONTENT:
            self.drop_depth += 1
            return
        if self.drop_depth or tag not in _LEGACY_ALLOWED_TAGS:
            return
        clean = ''
        if tag == 'a':
            href = _sanitize_url(dict(attrs).get('href') or '')
            clean = f' href="{escape(href)}" rel="nofollow noopener noreferrer"'
        elif tag == 'img':
            src = _sanitize_url(dict(attrs).get('src') or '', allow_data=True)
            clean = f' src="{escape(src)}" alt="image"'
        if tag in ('img', 'span'):
            style = (dict(attrs).get('style') or '').strip()
            if style and _LEGACY_STYLE_RE.match(style):
                clean += f' style="{escape(style)}"'
        self.out.append(f'<{tag}{clean}>')
        if tag not in _LEGACY_VOID_TAGS:
            self.open_tags.append(tag)

    def handle_startendtag(self, tag, attrs):
        if tag in _LEGACY_DROP_CONTENT:
            return
        self.handle_starttag(tag, attrs)
        if tag not in _LEGACY_VOID_TAGS and self.open_tags and not self.drop_depth \
                and tag in _LEGACY_ALLOWED_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in _LEGACY_DROP_CONTENT:
            if self.drop_depth:
                self.drop_depth -= 1
            return
        if self.drop_depth or tag not in self.open_tags:
            return
        # Ferme jusqu'a la balise ouvrante correspondante : HTML toujours bien forme.
        while self.open_tags:
            top = self.open_tags.pop()
            self.out.append(f'</{top}>')
            if top == tag:
                break

    def handle_data(self, data):
        if not self.drop_depth:
            self.out.append(str(escape(data)))

    def result(self):
        while self.open_tags:
            self.out.append(f'</{self.open_tags.pop()}>')
        return ''.join(self.out)


def sanitize_legacy_html(raw: str) -> str:
    """Assainit le HTML d'un ancien commentaire (liste blanche, sans script)."""
    if not raw:
        return ''
    parser = _LegacyHTMLSanitizer()
    try:
        parser.feed(raw)
        parser.close()
    except Exception:
        return str(escape(raw))
    return parser.result()


def html_to_text(raw: str) -> str:
    """Texte brut d'un ancien commentaire HTML (pre-remplissage de l'edition).

    Uniquement en memoire : la ligne en base n'est pas modifiee.
    """
    if not raw:
        return ''
    text = re.sub(r'<(script|style)\b.*?</\1\s*>', '', raw, flags=re.I | re.S)
    text = re.sub(r'<[^>]*>', '', text)
    return _html.unescape(text)


# -----------------------------
# Media pipeline: strip EXIF, resize, convert to WebP
# -----------------------------

def strip_exif(image: Image.Image) -> Image.Image:
    """Copie de l'image sans metadonnees.

    `copy()` reste au niveau du tampon C : l'ancienne version passait par
    `list(getdata())`, soit un objet Python par pixel (3,6 Go pour un PNG
    uni de 6000x6600).
    """
    try:
        image.load()
        clean = image.copy()
        clean.info = {}
        return clean
    except Exception:
        return image

def resize_image(image: Image.Image, max_px: int = 1600) -> Image.Image:
    w, h = image.size
    if max(w, h) <= max_px:
        return image
    image = image.copy()
    image.thumbnail((max_px, max_px))
    return image

def process_image_file(src_path: str, max_px: int = 1600, save_webp: bool = True) -> str:
    """Process uploaded image: strip EXIF, resize, save as WebP next to original.
    Returns path to processed file (webp if enabled else original updated).
    """
    try:
        with Image.open(src_path) as img:
            img = strip_exif(img)
            img = resize_image(img, max_px=max_px)
            base, ext = os.path.splitext(src_path)
            if save_webp:
                out_path = base + '.webp'
                img.save(out_path, 'WEBP', quality=88, method=6)
                return out_path
            else:
                # overwrite original as JPEG to drop metadata
                out_path = base + '.jpg'
                img.convert('RGB').save(out_path, 'JPEG', quality=88)
                return out_path
    except Exception as e:
        print('Image processing error:', e)
        return src_path


# -----------------------------
# Roles without schema change (mapping via is_admin/level)
# -----------------------------

def user_has_role(user, role: str) -> bool:
    role = (role or '').lower()
    if role == 'admin':
        return bool(getattr(user, 'is_admin', False))
    if role == 'moderator':
        return bool(getattr(user, 'is_admin', False)) or int(getattr(user, 'level', 1)) >= 5
    if role == 'author':
        return getattr(user, 'is_authenticated', False)
    if role == 'reader':
        return True
    return False

def role_required(allowed_roles):
    if isinstance(allowed_roles, str):
        allowed = [allowed_roles]
    else:
        allowed = list(allowed_roles)
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask_login import current_user
            if not getattr(current_user, 'is_authenticated', False):
                flash('Authentication required', 'danger')
                return redirect(url_for('login'))
            for r in allowed:
                if user_has_role(current_user, r):
                    return func(*args, **kwargs)
            flash('Insufficient permissions', 'danger')
            return redirect(url_for('index'))
        return wrapper
    return decorator


# -----------------------------
# Simple rate limiter (in-memory)
# Compatible NoScript (server-side only)
# -----------------------------
_RATE_LIMIT_STORE = {}
_RATE_LIMIT_LOCK = threading.Lock()

# Au-dela de ce nombre de cles, on purge celles dont le dernier evenement date
# de plus d'une heure : sans cela, chaque client distinct laissait une entree
# en memoire jusqu'au redemarrage.
_STORE_MAX_KEYS = 10_000
_STORE_MAX_AGE = 3600

# Sel ephemere, regenere a chaque demarrage : les cles du limiteur ne sont donc
# jamais correlables entre deux redemarrages, et une copie de la memoire du
# processus ne permet pas de remonter aux adresses IP.
_CLIENT_SALT = os.urandom(32)


def purge_store(store: dict, now: float = None, max_keys: int = None, max_age: int = None):
    """Retire les cles inactives d'un dict {cle: [horodatages]} s'il est trop gros.

    L'appelant tient son verrou. Sans effet tant que le dict reste sous la limite.
    """
    max_keys = max_keys or _STORE_MAX_KEYS
    if len(store) <= max_keys:
        return
    now = now or time.time()
    cutoff = now - (max_age or _STORE_MAX_AGE)
    for key in [k for k, stamps in store.items() if not stamps or max(stamps) < cutoff]:
        store.pop(key, None)


def anonymous_client_key() -> str:
    """Identifiant de client pour le rate limiting, sans stocker d'adresse IP.

    On hache l'IP avec un sel ephemere : le limiteur distingue toujours deux
    visiteurs, mais aucune adresse IP en clair ne subsiste en memoire.
    """
    try:
        from flask_login import current_user
        if getattr(current_user, 'is_authenticated', False):
            return f"user:{current_user.id}"
    except Exception:
        pass
    raw = (request.remote_addr or 'unknown').encode()
    return 'anon:' + hashlib.blake2b(raw, key=_CLIENT_SALT, digest_size=16).hexdigest()


def hashed_key(value: str) -> str:
    """Empreinte salee d'une valeur saisie (pseudo...) pour servir de cle."""
    return hashlib.blake2b((value or '').encode(), key=_CLIENT_SALT, digest_size=16).hexdigest()


def rate_limit(key_prefix: str, max_calls: int, window_seconds: int):
    """Simple rate limit decorator using in-memory store per IP/user.
    - key_prefix: logical endpoint name
    - max_calls: allowed calls within the window
    - window_seconds: time window

    Seules les requetes POST sont comptees : derriere un service onion tous les
    visiteurs partagent la meme adresse, et compter les GET suffisait a bloquer
    la page de connexion pour tout le site.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method != 'POST':
                return func(*args, **kwargs)
            now = time.time()
            key = f"{key_prefix}:{anonymous_client_key()}"
            with _RATE_LIMIT_LOCK:
                bucket = _RATE_LIMIT_STORE.get(key, [])
                # purge old timestamps
                bucket = [t for t in bucket if t > now - window_seconds]
                limited = len(bucket) >= max_calls
                if not limited:
                    bucket.append(now)
                _RATE_LIMIT_STORE[key] = bucket
                purge_store(_RATE_LIMIT_STORE, now)
            if limited:
                flash('Too many requests. Please slow down.', 'danger')
                # Retour a la page precedente, seulement si elle est sur ce site :
                # `Referer` est controle par le client (redirection ouverte).
                ref = request.referrer
                if not ref or urlparse(ref).netloc != request.host:
                    ref = url_for('index')
                return redirect(ref)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------------
# Compteur d'echecs (verrouillage par identifiant : connexion, API mobile)
# -----------------------------
_FAILURE_STORE = {}
_FAILURE_LOCK = threading.Lock()
_FAILURE_MAX_WINDOW = 3600


def record_failure(key: str) -> None:
    now = time.time()
    with _FAILURE_LOCK:
        stamps = [t for t in _FAILURE_STORE.get(key, []) if t > now - _FAILURE_MAX_WINDOW]
        stamps.append(now)
        _FAILURE_STORE[key] = stamps
        purge_store(_FAILURE_STORE, now)


def too_many_failures(key: str, max_calls: int, window_seconds: int) -> bool:
    now = time.time()
    with _FAILURE_LOCK:
        stamps = [t for t in _FAILURE_STORE.get(key, []) if t > now - window_seconds]
    return len(stamps) >= max_calls


def clear_failures(key: str) -> None:
    with _FAILURE_LOCK:
        _FAILURE_STORE.pop(key, None)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def publish_scheduled_posts():
    """Publie les articles programmes dont la date est passee.

    Un article sans date (brouillon) n'est jamais publie automatiquement.
    """
    now = datetime.utcnow()
    due = (Post.query.filter(Post.is_published.is_(False),
                             Post.scheduled_date.isnot(None),
                             Post.scheduled_date <= now).all())
    if not due:
        return
    for post in due:
        post.is_published = True
        post.is_draft = False
    db.session.commit()
