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
from PIL import Image, ExifTags
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

def _sanitize_url(url: str) -> str:
    url = (url or '').strip()
    if not url:
        return '#'
    # allow only http/https/data:image
    if not (url.lower().startswith('http://') or url.lower().startswith('https://') or url.lower().startswith('data:image')):
        return '#'
    return url

def parse_bbcode(text: str) -> str:
    if not text:
        return ''
    html = text
    # [url=...]text[/url] and [url]link[/url]
    html = re.sub(r"\[url=(.+?)\](.*?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener\">{m.group(2)}</a>", html, flags=re.IGNORECASE)
    html = re.sub(r"\[url\](.+?)\[/url\]", lambda m: f"<a href=\"{_sanitize_url(m.group(1))}\" rel=\"nofollow noopener\">{m.group(1)}</a>", html, flags=re.IGNORECASE)
    # [img]...[/img] and [img=width,height]...[/img]
    def _img_simple(m):
        src = _sanitize_url(m.group(1))
        return f"<img src=\"{src}\" alt=\"image\" style=\"max-width:100%;height:auto;\">"
    html = re.sub(r"\[img\](.+?)\[/img\]", _img_simple, html, flags=re.IGNORECASE)
    def _img_sized(m):
        dims = m.group(1).split(',')
        try:
            w = int(dims[0]) if dims[0] else 0
            h = int(dims[1]) if len(dims) > 1 else 0
        except Exception:
            w, h = 0, 0
        src = _sanitize_url(m.group(2))
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
# Media pipeline: strip EXIF, resize, convert to WebP
# -----------------------------

def strip_exif(image: Image.Image) -> Image.Image:
    try:
        data = list(image.getdata())
        clean = Image.new(image.mode, image.size)
        clean.putdata(data)
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

def rate_limit(key_prefix: str, max_calls: int, window_seconds: int):
    """Simple rate limit decorator using in-memory store per IP/user.
    - key_prefix: logical endpoint name
    - max_calls: allowed calls within the window
    - window_seconds: time window
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            client_id = None
            try:
                from flask_login import current_user
                if current_user.is_authenticated:
                    client_id = f"user:{current_user.id}"
            except Exception:
                client_id = None
            if not client_id:
                client_id = f"ip:{request.remote_addr}"

            key = f"{key_prefix}:{client_id}"
            bucket = _RATE_LIMIT_STORE.get(key, [])
            # purge old timestamps
            bucket = [t for t in bucket if t > now - window_seconds]
            if len(bucket) >= max_calls:
                flash('Too many requests. Please slow down.', 'danger')
                # Gently redirect back
                ref = request.referrer or url_for('index')
                return redirect(ref)
            bucket.append(now)
            _RATE_LIMIT_STORE[key] = bucket
            return func(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def publish_scheduled_posts():
    now = datetime.utcnow()
    scheduled_posts = Post.query.filter_by(is_published=False).filter(Post.scheduled_date <= now).all()
    for post in scheduled_posts:
        post.is_published = True
        db.session.commit()
