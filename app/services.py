"""Shared helpers used by the web routes and the mobile API
(auth helpers, uploads, chat, deletion cascades, notifications)."""
from flask import url_for, flash, redirect, request, session, has_request_context
from flask_login import current_user
from app import app, db, bcrypt
from app.models import User, Post, Comment, Revision, Message, Like, Notification, Badge, Tag
from app.utils import process_image_file, hit_rate_limit, anonymous_client_key
from app.encryption import message_encryption
from functools import wraps
from datetime import datetime
import re
import hashlib
import json
import os
import queue
import time
from threading import Lock
from PIL import Image
from sqlalchemy.exc import IntegrityError
import pyotp
import hmac
import secrets


# Admin-only route decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Access denied. Only admins can view this page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def _get_admin_user_id() -> int:
    """Return the ID of the first admin user, falling back to user ID 1."""
    admin = User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()
    if admin:
        return admin.id
    return 1


# Mobile admin API helpers (Basic Auth + SSE stream)
mobile_event_subscribers = []
mobile_event_lock = Lock()


def _to_positive_int(text):
    try:
        value = int(str(text).strip())
        return value if value > 0 else None
    except Exception:
        return None


def _action_rate_limited(action_key, max_calls, window_seconds, actor_key=None):
    """True if the actor exceeded `max_calls` in `window_seconds`.

    `actor_key` replaces the client key: useful when the limit must apply to a
    target account (pending 2FA) and not to the current visitor. Keys are
    hashed before they are stored (see utils.hit_rate_limit).
    """
    if actor_key is None:
        actor_key = anonymous_client_key()
    return hit_rate_limit(f"{action_key}:{actor_key}", max_calls, window_seconds)


def serialize_chat_message(message):
    decrypted_content = message.get_decrypted_content() if message.is_encrypted else message.content
    file_url = None
    if message.file_path:
        filename = message.file_path.split('/')[-1]
        if has_request_context():
            file_url = url_for('uploaded_file', filename=filename, _external=True)
        else:
            file_url = f"/uploads/{filename}"

    return {
        'id': message.id,
        'sender_id': message.sender_id,
        'sender_username': message.sender.username if message.sender else None,
        'sender_is_admin': message.sender.is_admin if message.sender else False,
        'receiver_id': message.receiver_id,
        'receiver_username': message.receiver.username if message.receiver else None,
        'content': decrypted_content,
        'file_path': message.file_path,
        'file_url': file_url,
        'file_type': message.file_type,
        'is_encrypted': message.is_encrypted,
        'timestamp': message.timestamp.isoformat() if message.timestamp else None
    }


def publish_mobile_event(event_type, payload):
    event = {
        'type': event_type,
        'payload': payload,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }

    with mobile_event_lock:
        for subscriber in list(mobile_event_subscribers):
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                continue


def _project_root():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def _uploads_root():
    return os.path.abspath(os.path.join(_project_root(), UPLOAD_FOLDER))


def _absolute_upload_path(stored_path, root=None):
    """Absolute path of an upload, bounded to the uploads folder.

    `stored_path` is "uploads/<name>" (current) or a bare file name (older
    rows); anything that would leave the uploads folder is rejected (None).
    """
    if not stored_path:
        return None
    root = os.path.abspath(root) if root else _uploads_root()
    if os.path.isabs(stored_path):
        candidate = stored_path
    else:
        candidate = os.path.join(root, os.path.basename(stored_path))
    candidate = os.path.abspath(candidate)
    if os.path.commonpath([candidate, root]) != root:
        return None
    return candidate


def _first_admin_user():
    return User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()


def _conversation_latest_message_id(admin_id, user_id):
    latest = Message.query.filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id))
    ).order_by(Message.id.desc()).first()
    return latest.id if latest else 0

def _delete_post_and_children(post):
    """Delete a post and every row that points to it or to its comments.

    Rows that reference the post or its comments (NOT NULL or foreign key) must
    go before it, otherwise IntegrityError -> 500. Notifications are kept but
    detached. Raises IntegrityError (after a rollback) if it still cannot be
    deleted.
    """
    comment_ids = [c.id for c in Comment.query.filter_by(post_id=post.id).all()]
    post_id = post.id
    try:
        Like.query.filter_by(post_id=post_id).delete(synchronize_session=False)
        if comment_ids:
            Like.query.filter(Like.comment_id.in_(comment_ids)) \
                .delete(synchronize_session=False)
            Notification.query.filter(Notification.related_comment_id.in_(comment_ids)) \
                .update({'related_comment_id': None}, synchronize_session=False)
            Comment.query.filter(Comment.id.in_(comment_ids)) \
                .update({'parent_id': None}, synchronize_session=False)
        Notification.query.filter_by(related_post_id=post_id) \
            .update({'related_post_id': None}, synchronize_session=False)
        if comment_ids:
            Comment.query.filter(Comment.id.in_(comment_ids)) \
                .delete(synchronize_session=False)
        Revision.query.filter_by(post_id=post_id).delete(synchronize_session=False)
        db.session.expire_all()
        target = db.session.get(Post, post_id)
        target.tags = []
        db.session.delete(target)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise


def slugify(text, max_len=50):
    return re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')[:max_len]


def apply_post_taxonomy(post, category_text, tags_text):
    """Set a post's category (free text) and tags (comma separated)."""
    category = re.sub(r'\s+', ' ', (category_text or '').strip())[:60]
    post.category = category if slugify(category) else None
    tags = []
    for raw in (tags_text or '').split(','):
        name = re.sub(r'\s+', ' ', raw.strip())[:40]
        slug = slugify(name)
        if not slug or any(t.slug == slug for t in tags):
            continue
        tag = Tag.query.filter_by(slug=slug).first()
        if not tag:
            tag = Tag(name=name, slug=slug)
            db.session.add(tag)
        tags.append(tag)
        if len(tags) >= 10:
            break
    post.tags = tags


def _visible_posts_query():
    """Drafts / unpublished posts are only visible to admins."""
    query = Post.query
    if not (current_user.is_authenticated and current_user.is_admin):
        query = query.filter(Post.is_published.is_(True))
    return query


# Login
# Constant-time-ish login: always run one bcrypt check, even for unknown users,
# so response timing does not reveal which usernames exist.
_DUMMY_PASSWORD_HASH = bcrypt.generate_password_hash(secrets.token_hex(16)).decode('utf-8')


def _check_user_password(user, password):
    if not password or len(password.encode('utf-8')) > 72:
        bcrypt.check_password_hash(_DUMMY_PASSWORD_HASH, 'x')
        return False
    if not user:
        bcrypt.check_password_hash(_DUMMY_PASSWORD_HASH, password)
        return False
    try:
        return bcrypt.check_password_hash(user.password, password)
    except ValueError:
        return False


def _start_fresh_session():
    """Drop everything from the pre-login session (session fixation)."""
    session.clear()
    session.permanent = True


# TOTP: a code is valid for one 30 s step, with a tolerance of one step on
# each side. The accepted step is stored (User.totp_last_counter): a code
# that was already used cannot be replayed.
TOTP_STEP_SECONDS = 30


def _totp_secret(user):
    """Plain TOTP secret. An old unencrypted value is returned as is."""
    if not user or not user.totp_secret:
        return None
    return message_encryption.decrypt_message(user.totp_secret)


def _store_totp_secret(user, secret):
    user.totp_secret = message_encryption.encrypt_message(secret)


def _verify_totp_once(user, code, allow_reuse=False, secret=None):
    """Verify a TOTP code (+/-1 step) and reject replays of an already used code.

    allow_reuse=True is for stateless API calls that send the code on every
    request. On success the user's counter is updated; the caller commits.
    """
    secret = secret or _totp_secret(user)
    code = re.sub(r'\s+', '', code or '')
    if not user or not secret or not re.fullmatch(r'\d{6}', code):
        return False
    last = user.totp_last_counter if user.totp_last_counter is not None else -1
    # Unix timestamp (not a naive datetime: pyotp would read it as local time)
    current = int(time.time()) // TOTP_STEP_SECONDS
    try:
        generator = pyotp.TOTP(secret)
        for counter in (current - 1, current, current + 1):
            if hmac.compare_digest(generator.generate_otp(counter), code):
                if allow_reuse:
                    return True
                if counter > last:
                    user.totp_last_counter = counter
                    # Old plaintext secret: encrypt it now that it is proven valid.
                    if user.totp_secret and user.totp_secret == secret:
                        _store_totp_secret(user, secret)
                    return True
                return False
    except Exception:
        return False
    return False


# 2FA recovery codes
RECOVERY_CODE_COUNT = 10


def _hash_recovery_code(code):
    return hashlib.sha256(code.strip().upper().replace('-', '').encode()).hexdigest()


def generate_recovery_codes(user):
    """Create a fresh set of one-time recovery codes. Only their SHA-256 is
    stored (the codes are random, 50 bits each, so a fast hash is enough).
    Returns the plaintext codes: they are shown to the user exactly once."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # no 0/O/1/I confusion
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = ''.join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    user.recovery_codes = json.dumps([_hash_recovery_code(c) for c in codes])
    return codes


def recovery_codes_left(user):
    try:
        return len(json.loads(user.recovery_codes or '[]'))
    except ValueError:
        return 0


def use_recovery_code(user, code):
    """Consume a recovery code (each works once). Commits on success."""
    if not user or not code or not re.fullmatch(r'[A-Za-z0-9]{5}-?[A-Za-z0-9]{5}', code.strip()):
        return False
    try:
        hashes = json.loads(user.recovery_codes or '[]')
    except ValueError:
        return False
    wanted = _hash_recovery_code(code)
    match = next((h for h in hashes if hmac.compare_digest(h, wanted)), None)
    if not match:
        return False
    hashes.remove(match)
    user.recovery_codes = json.dumps(hashes)
    db.session.commit()
    security_alert(f"2FA recovery code used by @{user.username} ({len(hashes)} left)")
    return True


def verify_second_factor(user, code):
    """TOTP code (one-time) or recovery code."""
    code = (code or '').strip()
    if re.fullmatch(r'\d{6}', code):
        if _verify_totp_once(user, code):
            db.session.commit()   # persists the replay counter
            return True
        return False
    return use_recovery_code(user, code)


# Sessions
def invalidate_other_sessions(user):
    """Log the user out everywhere (sessions + remember-me cookies) by bumping
    session_version; the caller logs the current browser back in."""
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()


# Security alerts: written to the application log only (nothing leaves the
# server; the former Telegram bridge was removed on purpose).
def security_alert(text):
    """Record a security event in the log. Never raises."""
    try:
        app.logger.warning("SECURITY %s", text)
    except Exception:  # nosec B110
        pass


# Personal data export
def export_user_data(user):
    """Everything the blog stores about a user, readable (messages decrypted)."""
    def iso(dt):
        return dt.isoformat() + 'Z' if dt else None
    messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)
    ).order_by(Message.timestamp.asc()).all()
    return {
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'account': {
            'id': user.id,
            'username': user.username,
            'created_at': iso(user.created_at),
            'is_admin': bool(user.is_admin),
            'level': user.level,
            'experience_points': user.experience_points,
            'badges': user.get_badges(),
            'two_factor_enabled': bool(user.totp_enabled),
            'has_profile_picture': bool(user.profile_picture),
        },
        'comments': [
            {'id': c.id, 'post_id': c.post_id, 'parent_id': c.parent_id,
             'content': c.content, 'date': iso(c.date_posted), 'deleted': bool(c.deleted)}
            for c in Comment.query.filter_by(author_id=user.id).order_by(Comment.id).all()
        ],
        'posts': [
            {'id': p.id, 'title': p.title, 'content': p.content, 'date': iso(p.date_posted),
             'published': bool(p.is_published)}
            for p in Post.query.filter_by(author_id=user.id).order_by(Post.id).all()
        ],
        'messages': [
            {'id': m.id, 'direction': 'sent' if m.sender_id == user.id else 'received',
             'content': m.get_decrypted_content() if m.is_encrypted else m.content,
             'has_attachment': bool(m.file_path), 'date': iso(m.timestamp)}
            for m in messages
        ],
        'likes': [
            {'post_id': like.post_id, 'comment_id': like.comment_id, 'date': iso(like.created_at)}
            for like in Like.query.filter_by(user_id=user.id).all()
        ],
        'notifications': [
            {'type': n.type, 'title': n.title, 'message': n.message, 'read': bool(n.is_read),
             'date': iso(n.created_at)}
            for n in Notification.query.filter_by(user_id=user.id).order_by(Notification.id).all()
        ],
    }


# File Upload Configuration
UPLOAD_FOLDER = 'uploads'
MAX_UPLOAD_BYTES = int((os.environ.get('MAX_UPLOAD_BYTES') or str(10 * 1024 * 1024)).strip())
# SECURITY: no svg / xml / html: they can carry scripts when served from our origin.
CHAT_ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp',
    'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', '7z',
    'mp3', 'mp4', 'avi', 'mov', 'mkv', 'csv', 'xls', 'xlsx',
    'ppt', 'pptx', 'json', 'webm', 'ogg'
}
PROFILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
# Guard rails against decompression bombs. 40 megapixels lets every consumer
# camera through; beyond that the image is forged. Same limit everywhere,
# including the code paths that do not call _validate_uploaded_file.
MAX_IMAGE_PIXELS = 40_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
MAX_IMAGE_SIDE = 12_000
ALLOWED_MIME_EXACT = {
    'application/pdf', 'application/zip', 'application/json', 'application/xml',
    'application/msword', 'application/octet-stream',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/x-7z-compressed', 'application/x-rar-compressed', 'application/vnd.rar',
    'application/x-zip-compressed', 'text/plain', 'text/csv'
}
ALLOWED_MIME_PREFIXES = ('image/', 'video/', 'audio/')
BLOCKED_MIME_TYPES = {'image/svg+xml', 'text/html', 'application/xhtml+xml', 'text/xml', 'application/xml'}


def _file_ext(filename):
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower().strip()


def allowed_file(filename, allowed_exts=None):
    allowed_exts = allowed_exts or CHAT_ALLOWED_EXTENSIONS
    return _file_ext(filename) in allowed_exts


def _validate_uploaded_file(file_obj, allowed_exts=None, max_bytes=None, image_only=False):
    if not file_obj or not getattr(file_obj, 'filename', ''):
        return False, "No file selected."
    allowed_exts = allowed_exts or CHAT_ALLOWED_EXTENSIONS
    max_bytes = max_bytes or MAX_UPLOAD_BYTES
    ext = _file_ext(file_obj.filename)
    if ext not in allowed_exts:
        return False, "File extension not allowed."

    stream = file_obj.stream
    current_pos = stream.tell()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(current_pos)
    if size <= 0:
        return False, "Empty file."
    if size > max_bytes:
        return False, f"File too large (max {max_bytes // (1024 * 1024)} MB)."

    mime = (getattr(file_obj, 'mimetype', '') or '').lower().strip()
    if mime in BLOCKED_MIME_TYPES:
        return False, "Unsupported MIME type."
    if image_only:
        if not mime.startswith('image/'):
            return False, "Only image uploads are allowed."
    elif not (mime in ALLOWED_MIME_EXACT or any(mime.startswith(p) for p in ALLOWED_MIME_PREFIXES)):
        return False, "Unsupported MIME type."

    if ext in IMAGE_EXTENSIONS:
        try:
            stream.seek(0)
            with Image.open(stream) as img:
                # Decompression bomb: a PNG of a few kilobytes can declare
                # 50000x50000 pixels. Refuse on the declared size BEFORE
                # decoding anything.
                width, height = img.size
                if width * height > MAX_IMAGE_PIXELS or \
                        width > MAX_IMAGE_SIDE or height > MAX_IMAGE_SIDE:
                    stream.seek(0)
                    return False, "Image dimensions are too large."
                img.verify()
            stream.seek(0)
        except Exception:
            stream.seek(0)
            return False, "Invalid or corrupted image."

    return True, ""

# Uploaded files are encrypted at rest with the same key as chat messages.
ENCRYPTED_SUFFIX = '.enc'


def encrypt_upload_in_place(absolute_path):
    """Encrypt a plaintext file on disk; returns the new path (<name>.enc).
    Written to a temporary file first, the plaintext is removed only once the
    ciphertext is safely on disk and decrypts back to the same bytes."""
    from app.encryption import message_encryption
    with open(absolute_path, 'rb') as f:
        plain = f.read()
    token = message_encryption.encrypt_bytes(plain)
    if message_encryption.decrypt_bytes(token) != plain:
        raise RuntimeError('encryption self-check failed')
    target = absolute_path + ENCRYPTED_SUFFIX
    tmp = target + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(token)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)
    os.remove(absolute_path)
    return target


def read_upload_bytes(stored_path):
    """Plaintext content of an upload (decrypted when stored encrypted)."""
    absolute = _absolute_upload_path(stored_path)
    if not absolute:
        raise FileNotFoundError(stored_path)
    with open(absolute, 'rb') as f:
        data = f.read()
    if absolute.endswith(ENCRYPTED_SUFFIX):
        from app.encryption import message_encryption
        data = message_encryption.decrypt_bytes(data)
    return data


def upload_display_name(stored_path):
    """File name without the .enc suffix (used for MIME type / download name)."""
    name = os.path.basename(stored_path or '')
    return name[:-len(ENCRYPTED_SUFFIX)] if name.endswith(ENCRYPTED_SUFFIX) else name


class UploadRefused(Exception):
    """The upload matched the block list: the file is quarantined and the
    author banned. `str(exc)` is the message to show."""


def screen_uploaded_image(file_path, user):
    """Refuse an image that is on the blocked-hash list.

    Returns None if the image passes. Otherwise: quarantines the file, bans the
    author, logs the event and returns an error message.

    To be called BEFORE the image is re-encoded: re-encoding changes its
    SHA-256 (the perceptual dHash survives both).
    """
    from app.image_safety import check_image, quarantine_file, sha256_of_file
    from app.models import BlockedUploadEvent

    try:
        match, distance = check_image(path=file_path)
    except Exception:
        # A failing check must neither let the image through silently nor block
        # a legitimate upload: log it and let it pass.
        app.logger.exception('Image screening failed; upload allowed unchecked.')
        return None

    if match is None:
        return None

    digest = sha256_of_file(file_path)
    quarantined = quarantine_file(
        file_path,
        reason=f'hash match id={match.id} label={match.label or "-"} distance={distance}'
    )
    db.session.add(BlockedUploadEvent(
        user_id=getattr(user, 'id', None),
        matched_hash_id=match.id,
        distance=distance,
        sha256=digest,
        quarantine_name=quarantined,
    ))

    # Immediate ban of the author.
    if getattr(user, 'is_authenticated', False) and not user.is_admin:
        user.is_banned = True
        user.banned_at = datetime.utcnow()
        user.ban_reason = 'Blocked image upload'
        user.rotate_session_token()

    db.session.commit()
    app.logger.warning(
        'Blocked image upload: user_id=%s hash_id=%s distance=%s quarantine=%s',
        getattr(user, 'id', None), match.id, distance, quarantined
    )
    return 'This file cannot be uploaded.'


def strip_image_metadata(file_path):
    """Really remove the metadata of an image in place (EXIF, GPS, XMP, ICC),
    keeping its original format.

    The image is rebuilt from its pixels only: no metadata block survives.
    `copy()` works on the C buffer (no Python object per pixel). On failure the
    file is deleted rather than served with its GPS coordinates intact.

    The upload pipeline itself re-encodes images to WebP (process_image_file);
    this helper is kept for callers that need to keep the original format.
    """
    try:
        with Image.open(file_path) as image:
            fmt = image.format or 'PNG'
            image.load()
            keep = {k: image.info[k] for k in ('transparency',) if k in image.info}
            clean = image.copy()
            clean.info = dict(keep)
            if fmt.upper() in ('JPEG', 'JPG'):
                clean.convert('RGB').save(file_path, 'JPEG', quality=88)
            elif fmt.upper() == 'WEBP':
                clean.save(file_path, 'WEBP', quality=88, method=6)
            elif fmt.upper() == 'GIF':
                clean.save(file_path, fmt, **keep)
            else:
                clean.save(file_path, fmt)
    except Exception:
        app.logger.warning('Metadata stripping failed; upload discarded.')
        try:
            os.remove(file_path)
        except OSError:
            pass
        raise


def _store_upload(file_obj, prefix, user=None):
    """Save an already-validated upload under a random, unguessable name.

    Pipeline (order matters):
      1. image: checked against the block list on the original bytes
         (quarantine + ban on a match -> UploadRefused);
      2. image: re-encoded to WebP, ALL metadata stripped (EXIF, GPS, XMP...);
      3. every file is encrypted at rest (Fernet, ENCRYPTION_KEY).
    Returns (relative_path, file_type) or (None, None) if processing failed.
    The original filename is never used on disk (no overwrite of other users'
    files, no information leak, no guessable URL).
    """
    ext = _file_ext(file_obj.filename)
    filename = f"{prefix}_{secrets.token_urlsafe(18)}.{ext}"
    # Stored relative ("uploads/<name>"), written to the project's uploads
    # folder whatever the current working directory is.
    absolute_path = _absolute_upload_path(f"{UPLOAD_FOLDER}/{filename}")
    os.makedirs(os.path.dirname(absolute_path), exist_ok=True)
    file_obj.save(absolute_path)
    file_type = get_file_type(file_obj.filename)
    if ext in IMAGE_EXTENSIONS:
        refusal = screen_uploaded_image(absolute_path, user or current_user)
        if refusal:
            raise UploadRefused(refusal)
        processed = process_image_file(absolute_path)
        if not processed:
            try:
                os.remove(absolute_path)
            except OSError:
                pass
            return None, None
        absolute_path, file_type = processed, 'image'
    encrypted = encrypt_upload_in_place(absolute_path)
    return f"{UPLOAD_FOLDER}/{os.path.basename(encrypted)}", file_type


def _user_conversation_query(user_id):
    """Messages between *user_id* and any admin: what a user may see."""
    admin_ids = [u.id for u in User.query.filter_by(is_admin=True).all()]
    return Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id.in_(admin_ids))) |
        ((Message.receiver_id == user_id) & (Message.sender_id.in_(admin_ids)))
    )



UPLOAD_FILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def get_file_type(filename):
    """File type from the extension."""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv']:
        return 'video'
    else:
        return 'file'


def _remove_upload_file(stored_path):
    if not stored_path:
        return
    uploads_root = os.path.realpath(_uploads_root())
    path = _absolute_upload_path(stored_path)
    if not path:
        return
    real = os.path.realpath(path)
    if real.startswith(uploads_root + os.sep) and os.path.exists(real):
        try:
            os.remove(real)
        except OSError:
            pass


def _delete_user_and_data(user, new_post_owner_id, uploads_root=None):
    """Delete a user without leaving broken rows. Private data (messages,
    attachments, notifications, likes) is erased; posts are handed to
    `new_post_owner_id`; comments are anonymized to keep threads readable.
    Files only go once the database change is committed. Raises IntegrityError
    (after a rollback) if the account cannot be deleted."""
    from app.models import BlockedUploadEvent, SiteText, SiteTextRevision

    messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)).all()
    files = [m.file_path for m in messages if m.file_path]
    if user.profile_picture:
        files.append(user.profile_picture)
    try:
        Comment.query.filter_by(author_id=user.id).update({'author_id': None},
                                                          synchronize_session=False)
        for like in Like.query.filter_by(user_id=user.id).all():
            target = db.session.get(Post, like.post_id) if like.post_id \
                else db.session.get(Comment, like.comment_id)
            if target is not None:
                target.likes_count = max(0, (target.likes_count or 0) - 1)
            db.session.delete(like)
        for message in messages:
            db.session.delete(message)
        Notification.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        BlockedUploadEvent.query.filter_by(user_id=user.id) \
            .update({'user_id': None}, synchronize_session=False)
        SiteText.query.filter_by(updated_by_id=user.id) \
            .update({'updated_by_id': None}, synchronize_session=False)
        SiteTextRevision.query.filter_by(changed_by_id=user.id) \
            .update({'changed_by_id': None}, synchronize_session=False)
        Post.query.filter_by(author_id=user.id).update({'author_id': new_post_owner_id},
                                                       synchronize_session=False)
        db.session.flush()
        db.session.delete(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise

    for stored in files:
        path = _absolute_upload_path(stored, root=uploads_root)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


# Function to create default badges
# Badges were created with French names before the English-only cleanup.
_LEGACY_BADGE_NAMES = {
    'Premier Post': 'First Post',
    'Commentateur Actif': 'Active Commenter',
    'Auteur Prolifique': 'Prolific Author',
    'Populaire': 'Popular',
    'Niveau 5': 'Level 5',
}


def _rename_legacy_badges():
    """Rename old French badges in place (badge table + users' badge lists),
    so nobody loses a badge or earns the same one twice."""
    changed = False
    for old, new in _LEGACY_BADGE_NAMES.items():
        badge = Badge.query.filter_by(name=old).first()
        if badge and not Badge.query.filter_by(name=new).first():
            badge.name = new
            changed = True
    for user in User.query.filter(User.badges.isnot(None), User.badges != '').all():
        names = user.get_badges()
        renamed = [_LEGACY_BADGE_NAMES.get(n, n) for n in names]
        if renamed != names:
            user.badges = json.dumps(list(dict.fromkeys(renamed)))
            changed = True
    if changed:
        db.session.commit()


def create_default_badges():
    """Creates default system badges"""
    default_badges = [
        {
            'name': 'First Post',
            'description': 'Published their first post',
            'icon': 'fas fa-feather-alt',
            'color': '#8b93ff',
            'condition': 'first_post',
            'points_reward': 50
        },
        {
            'name': 'Active Commenter',
            'description': 'Posted 10 comments',
            'icon': 'fas fa-comments',
            'color': '#51cf66',
            'condition': '10_comments',
            'points_reward': 30
        },
        {
            'name': 'Prolific Author',
            'description': 'Published 5 posts',
            'icon': 'fas fa-pen-fancy',
            'color': '#ffd43b',
            'condition': '5_posts',
            'points_reward': 100
        },
        {
            'name': 'Popular',
            'description': 'One of their posts got 10 likes',
            'icon': 'fas fa-fire',
            'color': '#ff6b6b',
            'condition': '10_likes_post',
            'points_reward': 75
        },
        {
            'name': 'Level 5',
            'description': 'Reached level 5',
            'icon': 'fas fa-star',
            'color': '#9c88ff',
            'condition': 'level_5',
            'points_reward': 0
        }
    ]
    
    _rename_legacy_badges()
    for badge_data in default_badges:
        existing_badge = Badge.query.filter_by(name=badge_data['name']).first()
        if not existing_badge:
            badge = Badge(**badge_data)
            db.session.add(badge)
    
    db.session.commit()


# Function to check and award badges
def check_and_award_badges(user):
    """Checks and awards badges to a user"""
    badges = Badge.query.all()
    
    for badge in badges:
        if badge.name not in user.get_badges():
            should_award = False
            
            if badge.condition == 'first_post':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 1
            elif badge.condition == '10_comments':
                should_award = Comment.query.filter_by(author_id=user.id).count() >= 10
            elif badge.condition == '5_posts':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 5
            elif badge.condition == '10_likes_post':
                should_award = db.session.query(Post).filter_by(author_id=user.id)\
                    .filter(Post.likes_count >= 10).first() is not None
            elif badge.condition == 'level_5':
                should_award = user.level >= 5
            
            if should_award:
                user.add_badge(badge.name)
                user.add_experience(badge.points_reward)
                
                # Create notification
                notification = Notification(
                    user_id=user.id,
                    type='badge',
                    title='New badge earned!',
                    message=f'You earned the badge "{badge.name}": {badge.description}',
                )
                db.session.add(notification)
                
                flash(f'Congrats! You unlocked the badge "{badge.name}"!', 'success')
