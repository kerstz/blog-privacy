"""Shared helpers used by the web routes, the Telegram bot and the mobile API
(auth helpers, uploads, chat, deletion cascades, notifications)."""
from flask import url_for, flash, redirect, request, session, has_request_context
from flask_login import current_user
from app import db, bcrypt, socketio
from app.models import User, Post, Comment, Revision, Message, Like, Notification, Badge
from app.utils import process_image_file, hit_rate_limit, mark_totp_step_used
from functools import wraps
from datetime import datetime
import re
import json
import os
import queue
import time
from threading import Lock
from PIL import Image
import pyotp
import hmac
import secrets


# 🔹 Admin-only Route Decorator
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


# 🔹 Mobile admin API helpers (Basic Auth + SSE stream)
mobile_event_subscribers = []
mobile_event_lock = Lock()


def _to_positive_int(text):
    try:
        value = int(str(text).strip())
        return value if value > 0 else None
    except Exception:
        return None


def _action_rate_limited(action_key, max_calls, window_seconds):
    actor_key = f"ip:{request.remote_addr or 'unknown'}"
    if current_user.is_authenticated:
        actor_key = f"user:{current_user.id}"
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


def _absolute_upload_path(stored_path):
    if not stored_path:
        return None
    if os.path.isabs(stored_path):
        return stored_path
    return os.path.join(_project_root(), stored_path)


def _first_admin_user():
    return User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()


def _bridge_admin_user():
    """Return sender account used by Telegram bridge replies."""
    admin_user = _first_admin_user()
    if admin_user:
        return admin_user

    fallback_user = User.query.filter_by(id=1).first()
    if fallback_user:
        return fallback_user

    return User.query.order_by(User.id.asc()).first()


def _conversation_latest_message_id(admin_id, user_id):
    latest = Message.query.filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id))
    ).order_by(Message.id.desc()).first()
    return latest.id if latest else 0

def _delete_post_and_children(post):
    comment_ids = [c.id for c in Comment.query.filter_by(post_id=post.id).all()]
    if comment_ids:
        Like.query.filter(Like.comment_id.in_(comment_ids)).delete(synchronize_session=False)
        Notification.query.filter(Notification.related_comment_id.in_(comment_ids)).delete(synchronize_session=False)
        Comment.query.filter(Comment.id.in_(comment_ids)).delete(synchronize_session=False)
    Like.query.filter_by(post_id=post.id).delete(synchronize_session=False)
    Notification.query.filter_by(related_post_id=post.id).delete(synchronize_session=False)
    Revision.query.filter_by(post_id=post.id).delete(synchronize_session=False)
    db.session.delete(post)
    db.session.commit()


# 🔹 Home Page
def _visible_posts_query():
    """Drafts / unpublished posts are only visible to admins."""
    query = Post.query
    if not (current_user.is_authenticated and current_user.is_admin):
        query = query.filter(Post.is_published.is_(True))
    return query


def _user_room(user_id):
    return f"user_{int(user_id)}"


def _notify_user(user_id, payload):
    """Real-time event for ONE user (never broadcast: it leaked usernames,
    titles and chat content to every connected socket)."""
    if user_id:
        socketio.emit('notification', payload, to=_user_room(user_id))


# 🔹 Login a User
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


def _verify_totp_once(user, code, allow_reuse=False):
    """Verify a TOTP code (+/-1 step) and reject replays of an already used code
    (allow_reuse=True for stateless API calls that send the code on every request)."""
    if not user or not user.totp_secret or not code:
        return False
    code = code.strip()
    if not re.fullmatch(r'\d{6}', code):
        return False
    totp = pyotp.TOTP(user.totp_secret)
    # Unix timestamps (not naive datetimes: pyotp would read those as local time)
    now = int(time.time())
    for offset in (-1, 0, 1):
        at = now + offset * totp.interval
        if hmac.compare_digest(totp.at(at), code):
            step = at // totp.interval
            if allow_reuse:
                return True
            return mark_totp_step_used(user.id, step)
    return False


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
                img.verify()
            stream.seek(0)
        except Exception:
            stream.seek(0)
            return False, "Invalid or corrupted image."

    return True, ""

def _store_upload(file_obj, prefix):
    """Save an already-validated upload under a random, unguessable name.

    Images are re-encoded (all metadata stripped, WebP). Returns
    (relative_path, file_type) or (None, None) if processing failed.
    The original filename is never used on disk (no overwrite of other
    users' files, no information leak, no guessable URL).
    """
    ext = _file_ext(file_obj.filename)
    filename = f"{prefix}_{secrets.token_urlsafe(18)}.{ext}"
    # Stored relative ("uploads/<name>"), written to the project's uploads
    # folder whatever the current working directory is.
    absolute_path = _absolute_upload_path(f"{UPLOAD_FOLDER}/{filename}")
    os.makedirs(os.path.dirname(absolute_path), exist_ok=True)
    file_obj.save(absolute_path)
    if ext in IMAGE_EXTENSIONS:
        processed = process_image_file(absolute_path)
        if not processed:
            try:
                os.remove(absolute_path)
            except OSError:
                pass
            return None, None
        return f"{UPLOAD_FOLDER}/{os.path.basename(processed)}", 'image'
    return f"{UPLOAD_FOLDER}/{filename}", get_file_type(file_obj.filename)


def _user_conversation_query(user_id):
    """Messages between *user_id* and any admin: what a user may see."""
    admin_ids = [u.id for u in User.query.filter_by(is_admin=True).all()]
    return Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id.in_(admin_ids))) |
        ((Message.receiver_id == user_id) & (Message.sender_id.in_(admin_ids)))
    )


def _notify_admins_new_message(message):
    for admin in User.query.filter_by(is_admin=True).all():
        socketio.emit('new_message', {'message_id': message.id, 'from_user_id': message.sender_id},
                      to=_user_room(admin.id))



UPLOAD_FILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def get_file_type(filename):
    """File type from the extension."""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv']:
        return 'video'
    else:
        return 'file'


def _remove_upload_file(stored_path):
    if not stored_path:
        return
    uploads_root = os.path.realpath(_absolute_upload_path(UPLOAD_FOLDER))
    real = os.path.realpath(_absolute_upload_path(stored_path))
    if real.startswith(uploads_root + os.sep) and os.path.exists(real):
        try:
            os.remove(real)
        except OSError:
            pass


def _delete_user_and_data(user, new_post_owner_id):
    """Delete a user without leaving broken rows (the plain delete crashed
    with an IntegrityError / left orphans). Private data (messages,
    attachments, notifications, likes) is erased; posts are handed to an
    admin; comments are anonymized to keep threads readable."""
    for message in Message.query.filter((Message.sender_id == user.id) | (Message.receiver_id == user.id)).all():
        _remove_upload_file(message.file_path)
        db.session.delete(message)
    _remove_upload_file(user.profile_picture)
    Notification.query.filter_by(user_id=user.id).delete()
    for like in Like.query.filter_by(user_id=user.id).all():
        if like.post_id and like.post:
            like.post.likes_count = max(0, (like.post.likes_count or 0) - 1)
        if like.comment_id and like.comment:
            like.comment.likes_count = max(0, (like.comment.likes_count or 0) - 1)
        db.session.delete(like)
    Comment.query.filter_by(author_id=user.id).update({'author_id': None})
    Post.query.filter_by(author_id=user.id).update({'author_id': new_post_owner_id})
    db.session.delete(user)
    db.session.commit()


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
                
                _notify_user(user.id, {
                    'type': 'badge',
                    'title': 'New badge unlocked!',
                    'message': f'You unlocked the badge "{badge.name}": {badge.description}',
                })
                
                flash(f'Congrats! You unlocked the badge "{badge.name}"!', 'success')
