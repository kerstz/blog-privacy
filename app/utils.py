# app/utils.py
from app import db
from functools import wraps
from flask import redirect, url_for, flash, request
from flask_login import current_user
from app.models import Post
from datetime import datetime
import time
import threading
import random
import sqlite3
import re
from PIL import Image
import os
import nh3
from markupsafe import escape
from urllib.parse import urlparse, urljoin
from PIL import ImageOps


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

def _sanitize_url(url: str) -> str:
    """Allow only absolute http(s) URLs. Input is already HTML-escaped."""
    url = (url or '').strip()
    if not re.match(r'^https?://[^\s"\'<>]+$', url, re.IGNORECASE):
        return '#'
    return url

def _image_markup(url: str, extra_style: str) -> str:
    """Local images (/static/..., /uploads/...) are embedded. External images
    become a plain link: loading them would leak every reader's IP address
    to a third-party server (and the CSP blocks them anyway)."""
    url = (url or '').strip()
    if re.match(r'^/(?:static|uploads)/[A-Za-z0-9_./-]+$', url) and '..' not in url:
        style = 'max-width:100%;height:auto' + (';' + extra_style if extra_style else '')
        return f"<img src=\"{url}\" alt=\"image\" loading=\"lazy\" style=\"{style}\">"
    safe = _sanitize_url(url)
    if safe == '#':
        return '[image]'
    return f"<a href=\"{safe}\" rel=\"nofollow noopener noreferrer\">[external image: {safe}]</a>"


def parse_bbcode(text: str) -> str:
    """Convert user BBCode to HTML.

    SECURITY: the raw text is HTML-escaped *before* any tag is generated, so
    user input can never inject markup or attributes. The output is still
    passed through sanitize_user_html() at render time (defense in depth).
    """
    if not text:
        return ''
    html = str(escape(text))
    # [url=...]text[/url] and [url]link[/url]
    html = re.sub(r"\[url=(.+?)\](.*?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener noreferrer\">{m.group(2)}</a>", html, flags=re.IGNORECASE)
    html = re.sub(r"\[url\](.+?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener noreferrer\">{m.group(1)}</a>", html, flags=re.IGNORECASE)
    # [img]...[/img] and [img=width,height]...[/img]
    def _img_simple(m):
        return _image_markup(m.group(1), '')
    html = re.sub(r"\[img\](.+?)\[/img\]", _img_simple, html, flags=re.IGNORECASE)
    def _img_sized(m):
        dims = m.group(1).split(',')
        try:
            w = min(int(dims[0]), 2000) if dims[0] else 0
            h = min(int(dims[1]), 2000) if len(dims) > 1 and dims[1] else 0
        except Exception:
            w, h = 0, 0
        style = []
        if w > 0:
            style.append(f"max-width:{w}px")
        if h > 0:
            style.append(f"max-height:{h}px")
        return _image_markup(m.group(2), ';'.join(style))
    html = re.sub(r"\[img=(\d{0,4}(?:,\d{0,4})?)\](.+?)\[/img\]", _img_sized, html, flags=re.IGNORECASE)
    # lists [list] [*]item
    def _list_repl(m):
        items = re.findall(r"\[\*\](.+)", m.group(1))
        li = ''.join([f"<li>{it.strip()}</li>" for it in items])
        return f"<ul>{li}</ul>"
    html = re.sub(r"\[list\](.*?)\[/list\]", _list_repl, html, flags=re.IGNORECASE | re.DOTALL)
    def _olist_repl(m):
        items = re.findall(r"\[\*\](.+)", m.group(1))
        return "<ol>" + ''.join(f"<li>{it.strip()}</li>" for it in items) + "</ol>"
    html = re.sub(r"\[list=1\](.*?)\[/list\]", _olist_repl, html, flags=re.IGNORECASE | re.DOTALL)
    # alignment
    for align in ('center', 'left', 'right', 'justify'):
        html = re.sub(rf"\[{align}\](.*?)\[/{align}\]", rf'<p style="text-align:{align}">\1</p>', html, flags=re.IGNORECASE | re.DOTALL)
    # colors and sizes (strictly validated values)
    html = re.sub(r"\[color=(#[0-9a-fA-F]{3,6}|[a-zA-Z]{1,20})\](.*?)\[/color\]", r"<span style=\"color:\1\">\2</span>", html, flags=re.IGNORECASE | re.DOTALL)
    def _size_repl(m):
        size = max(8, min(int(m.group(1)), 48))
        return f"<span style=\"font-size:{size}px\">{m.group(2)}</span>"
    html = re.sub(r"\[size=(\d{1,3})\](.*?)\[/size\]", _size_repl, html, flags=re.IGNORECASE | re.DOTALL)
    # basic tags
    for pattern, repl in _BB_TAGS:
        html = pattern.sub(repl, html)
    # keep line breaks readable
    html = html.replace('\n', '<br>\n')
    return html


# -----------------------------
# HTML sanitization (nh3 / ammonia allow-list)
# -----------------------------

_URL_SCHEMES = {'http', 'https', 'mailto'}
_SAFE_STYLE_PROPS = {'color', 'font-size', 'max-width', 'max-height', 'height', 'width',
                     'text-align', 'font-weight', 'font-style', 'text-decoration'}

_USER_TAGS = {'a', 'b', 'strong', 'i', 'em', 'u', 's', 'blockquote', 'pre', 'code',
              'ul', 'ol', 'li', 'span', 'img', 'br', 'p'}
_USER_ATTRS = {
    'a': {'href'},
    'p': {'style'},
    'img': {'src', 'alt', 'style', 'loading'},
    'span': {'style'},
}

_RICH_TAGS = _USER_TAGS | {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'table', 'thead', 'tbody',
                           'tfoot', 'tr', 'th', 'td', 'caption', 'figure', 'figcaption',
                           'sub', 'sup', 'mark', 'small', 'del', 'ins', 'div', 'kbd', 'abbr'}
_RICH_ATTRS = {
    '*': {'class', 'style', 'title'},
    'a': {'href'},
    'img': {'src', 'alt', 'width', 'height', 'loading'},
    'td': {'colspan', 'rowspan'},
    'th': {'colspan', 'rowspan'},
}


def _local_images_only(tag, attr, value):
    """nh3 attribute filter: an <img> may only point to our own origin."""
    if tag == 'img' and attr == 'src':
        if re.match(r'^/(?:static|uploads)/[A-Za-z0-9_./-]+$', value or '') and '..' not in value:
            return value
        return None
    return value


def sanitize_user_html(html: str) -> str:
    """Sanitize HTML produced from user BBCode (comments/replies)."""
    return nh3.clean(html or '', tags=_USER_TAGS, attributes=_USER_ATTRS,
                     url_schemes=_URL_SCHEMES, link_rel='nofollow noopener noreferrer',
                     filter_style_properties=_SAFE_STYLE_PROPS,
                     attribute_filter=_local_images_only)


def sanitize_rich_html(html: str) -> str:
    """Sanitize admin HTML (posts, static pages, banners)."""
    return nh3.clean(html or '', tags=_RICH_TAGS, attributes=_RICH_ATTRS,
                     url_schemes=_URL_SCHEMES, link_rel='noopener noreferrer',
                     filter_style_properties=_SAFE_STYLE_PROPS,
                     attribute_filter=_local_images_only)


_ANY_HTML_TAG_RE = re.compile(r'<\s*/?\s*[a-zA-Z][a-zA-Z0-9]*(?:\s[^>]*)?/?>')


def render_rich_html(text: str) -> str:
    """Render a post / static page: HTML (legacy editor content) or BBCode."""
    text = text or ''
    if _ANY_HTML_TAG_RE.search(text):
        return sanitize_rich_html(text)
    return sanitize_rich_html(parse_bbcode(text))


def render_comment_html(text: str) -> str:
    """Render a stored comment. New comments are stored as raw BBCode; legacy
    rows may contain pre-rendered HTML. Both go through the sanitizer."""
    text = text or ''
    if _LEGACY_HTML_RE.search(text):
        return sanitize_user_html(text)
    return sanitize_user_html(parse_bbcode(text))


_LEGACY_HTML_RE = re.compile(r'</?(?:strong|em|u|s|blockquote|pre|code|a|img|ul|li|span|br|p)\b', re.IGNORECASE)


def is_safe_redirect_url(target: str) -> bool:
    if not target:
        return False
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ('http', 'https') and ref.netloc == test.netloc


# -----------------------------
# Media pipeline: strip EXIF, resize, convert to WebP
# -----------------------------

# Refuse absurdly large images (decompression bombs) early.
Image.MAX_IMAGE_PIXELS = 40_000_000


def strip_exif(image: Image.Image) -> Image.Image:
    """Return a copy of *image* with no metadata at all (EXIF, GPS, XMP, ICC,
    comments...). Orientation is applied first so the photo is not rotated."""
    try:
        image = ImageOps.exif_transpose(image)
    except Exception:
        pass
    if image.mode not in ('RGB', 'RGBA', 'L', 'LA'):
        image = image.convert('RGBA' if 'A' in image.getbands() or 'transparency' in image.info else 'RGB')
    clean = Image.new(image.mode, image.size)
    clean.paste(image)
    clean.info = {}
    return clean

def resize_image(image: Image.Image, max_px: int = 1600) -> Image.Image:
    w, h = image.size
    if max(w, h) <= max_px:
        return image
    image = image.copy()
    image.thumbnail((max_px, max_px))
    return image

def process_image_file(src_path: str, max_px: int = 1600, save_webp: bool = True) -> str:
    """Process uploaded image: strip ALL metadata, resize, re-encode as WebP.
    Returns the path of the processed file, or None if the file is not a
    decodable image (callers must then reject it)."""
    try:
        with Image.open(src_path) as img:
            img.load()
            img = strip_exif(img)
            img = resize_image(img, max_px=max_px)
            base, ext = os.path.splitext(src_path)
            if save_webp:
                out_path = base + '.webp'
                img.save(out_path, 'WEBP', quality=88, method=6)
            else:
                out_path = base + '.jpg'
                img.convert('RGB').save(out_path, 'JPEG', quality=88)
        if os.path.abspath(out_path) != os.path.abspath(src_path):
            try:
                os.remove(src_path)
            except OSError:
                pass
        return out_path
    except Exception as e:
        print('Image processing error:', e)
        return None


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
# Rate limiter + 2FA replay guard, persisted in SQLite
# (survives restarts, shared by every worker process)
# -----------------------------
_STATE_DB_PATH = os.environ.get('SECURITY_STATE_DB') or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'security_state.db')
_state_local = threading.local()
_STATE_LOCK = threading.Lock()


def _state_db():
    conn = getattr(_state_local, 'conn', None)
    if conn is None:
        os.makedirs(os.path.dirname(_STATE_DB_PATH), exist_ok=True)
        conn = sqlite3.connect(_STATE_DB_PATH, timeout=10, isolation_level=None)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE IF NOT EXISTS hits (key TEXT NOT NULL, ts REAL NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS hits_key_ts ON hits (key, ts)')
        conn.execute('CREATE TABLE IF NOT EXISTS totp_used (user_id INTEGER PRIMARY KEY, step INTEGER NOT NULL)')
        _state_local.conn = conn
    return conn


def _client_id():
    try:
        if current_user.is_authenticated:
            return f"user:{current_user.id}"
    except Exception:
        pass
    return f"ip:{request.remote_addr}"


def hit_rate_limit(key: str, max_calls: int, window_seconds: int, record: bool = True) -> bool:
    """Return True if *key* exceeded max_calls in the window (and optionally record a hit)."""
    now = time.time()
    with _STATE_LOCK:
        conn = _state_db()
        conn.execute('BEGIN IMMEDIATE')
        try:
            if random.random() < 0.01:
                conn.execute('DELETE FROM hits WHERE ts < ?', (now - 86400,))
            count = conn.execute('SELECT COUNT(*) FROM hits WHERE key = ? AND ts > ?',
                                 (key, now - window_seconds)).fetchone()[0]
            limited = count >= max_calls
            if record and not limited:
                conn.execute('INSERT INTO hits (key, ts) VALUES (?, ?)', (key, now))
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK')
            raise
    return limited


def mark_totp_step_used(user_id: int, step: int) -> bool:
    """Record a used TOTP time-step. False if this (or a later) step was already used."""
    with _STATE_LOCK:
        conn = _state_db()
        conn.execute('BEGIN IMMEDIATE')
        try:
            row = conn.execute('SELECT step FROM totp_used WHERE user_id = ?', (user_id,)).fetchone()
            if row and row[0] >= step:
                conn.execute('COMMIT')
                return False
            conn.execute('INSERT INTO totp_used (user_id, step) VALUES (?, ?) '
                         'ON CONFLICT(user_id) DO UPDATE SET step = excluded.step', (user_id, step))
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK')
            raise
    return True


def reset_security_state():
    """Clear rate limits and 2FA replay state (tests / admin maintenance)."""
    with _STATE_LOCK:
        conn = _state_db()
        conn.execute('DELETE FROM hits')
        conn.execute('DELETE FROM totp_used')


def rate_limit(key_prefix: str, max_calls: int, window_seconds: int, methods=('POST',)):
    """Simple rate limit decorator using in-memory store per IP/user.
    Only the given HTTP methods are counted (GET page views are free)."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method in methods:
                key = f"{key_prefix}:{_client_id()}"
                # Also limit per IP so switching accounts does not bypass it.
                ip_key = f"{key_prefix}:ip:{request.remote_addr}"
                if hit_rate_limit(key, max_calls, window_seconds) or \
                        (ip_key != key and hit_rate_limit(ip_key, max_calls * 3, window_seconds)):
                    flash('Too many requests. Please slow down.', 'danger')
                    ref = request.referrer
                    return redirect(ref if is_safe_redirect_url(ref) else url_for('index'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def publish_scheduled_posts():
    """Publish posts explicitly scheduled (not drafts) whose date has passed."""
    now = datetime.utcnow()
    scheduled_posts = Post.query.filter_by(is_published=False, is_draft=False)\
        .filter(Post.scheduled_date.isnot(None), Post.scheduled_date <= now).all()
    for post in scheduled_posts:
        post.is_published = True
    if scheduled_posts:
        db.session.commit()
