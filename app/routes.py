from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory, session, jsonify, Response, stream_with_context, has_request_context
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, socketio, csrf
from app.utils import parse_bbcode
from app.forms import LoginForm, RegistrationForm, PostForm, CommentForm, EmptyForm, BannerForm, StaticPageForm, ContactForm, ProfileEditForm, TOTPSetupForm, TOTPDisableForm, TOTPVerifyForm
from app.models import User, Post, Comment, Revision, Banner, StaticPage, Message, Donor, Like, Notification, Badge, ContactMessage
from app.utils import rate_limit, role_required, process_image_file
from functools import wraps
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from flask_socketio import emit
from werkzeug.utils import secure_filename
import re
import os
import sqlite3
import json
import base64
import queue
import time
import uuid
import requests
from threading import Lock, Thread
from PIL import Image
import piexif
import pyotp
import io


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
action_rate_limit_lock = Lock()
action_rate_limit_buckets = {}
telegram_update_lock = Lock()
telegram_last_update_id = 0
telegram_last_poll_at = 0.0
telegram_users_lock = Lock()
TELEGRAM_USERS_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'instance', 'telegram_users.db')
telegram_poller_started = False
telegram_poller_lock = Lock()
telegram_reply_state = {}
telegram_admin_state = {}
telegram_auth_sessions = {}
telegram_process_started_at = time.time()


def _ensure_telegram_users_db():
    os.makedirs(os.path.dirname(TELEGRAM_USERS_DB_PATH), exist_ok=True)
    with sqlite3.connect(TELEGRAM_USERS_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_users (
                chat_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                has_pending INTEGER DEFAULT 0,
                last_message TEXT,
                last_message_at TEXT,
                last_replied_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.commit()


def _telegram_users_upsert(chat_id, username, first_name, has_pending=None, last_message=None):
    _ensure_telegram_users_db()
    now_iso = datetime.utcnow().isoformat() + 'Z'

    with telegram_users_lock:
        with sqlite3.connect(TELEGRAM_USERS_DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO telegram_users (chat_id, username, first_name, has_pending, last_message, last_message_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET
                    username=excluded.username,
                    first_name=excluded.first_name,
                    updated_at=excluded.updated_at
                """,
                (chat_id, username, first_name, 0, None, None, now_iso)
            )

            if has_pending is not None:
                conn.execute(
                    "UPDATE telegram_users SET has_pending=?, updated_at=? WHERE chat_id=?",
                    (1 if has_pending else 0, now_iso, chat_id)
                )
            if last_message is not None:
                conn.execute(
                    "UPDATE telegram_users SET last_message=?, last_message_at=?, updated_at=? WHERE chat_id=?",
                    (last_message, now_iso, now_iso, chat_id)
                )
            conn.commit()


def _blog_non_admin_users():
    return User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()


def _blog_users_with_messages(admin_user_id):
    if not admin_user_id:
        return []

    users = _blog_non_admin_users()
    users_with_messages = []
    for user in users:
        has_user_message = Message.query.filter(
            Message.sender_id == user.id,
            Message.receiver_id == admin_user_id
        ).first() is not None
        if has_user_message:
            users_with_messages.append(user)
    return users_with_messages


def _blog_users_pending_reply(admin_user_id):
    if not admin_user_id:
        return []

    users = _blog_users_with_messages(admin_user_id)
    pending = []
    for user in users:
        latest_message = Message.query.filter(
            ((Message.sender_id == admin_user_id) & (Message.receiver_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.receiver_id == admin_user_id))
        ).order_by(Message.id.desc()).first()

        if latest_message and latest_message.sender_id == user.id:
            pending.append(user)
    return pending


def _format_blog_users_lines(title, users):
    if not users:
        return [f"{title}: none"]

    lines = [f"{title} ({len(users)}):"]
    for user in users[:60]:
        lines.append(f"- {user.username} (user_id={user.id})")
    if len(users) > 60:
        lines.append(f"...and {len(users) - 60} more.")
    return lines


def _telegram_set_admin_state(chat_id, mode, **payload):
    telegram_admin_state[chat_id] = {'mode': mode, **payload}


def _telegram_get_admin_state(chat_id):
    return telegram_admin_state.get(chat_id)


def _telegram_clear_admin_state(chat_id):
    telegram_admin_state.pop(chat_id, None)


def _telegram_admin_user_id():
    # Primary lock for Telegram actor identity (private user account).
    return (os.environ.get('TELEGRAM_ADMIN_USER_ID') or '').strip()


def _telegram_is_actor_authorized(actor_user_id):
    actor = str(actor_user_id or '').strip()
    explicit_admin = _telegram_admin_user_id()
    if explicit_admin:
        return actor == explicit_admin
    # Backward-compatible fallback: private bot chat uses same numeric id.
    configured_chat_id = (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    return bool(actor and configured_chat_id and actor == configured_chat_id)


def _telegram_pin_required():
    return bool((os.environ.get('TELEGRAM_ADMIN_PIN') or '').strip())


def _telegram_session_ttl_seconds():
    try:
        ttl = int((os.environ.get('TELEGRAM_ADMIN_SESSION_TTL') or '900').strip())
    except Exception:
        ttl = 900
    return max(300, min(ttl, 3600))


def _telegram_is_session_valid(actor_user_id):
    expiry = telegram_auth_sessions.get(str(actor_user_id or ''))
    return bool(expiry and time.time() < expiry)


def _telegram_start_session(actor_user_id):
    if not actor_user_id:
        return
    telegram_auth_sessions[str(actor_user_id)] = time.time() + _telegram_session_ttl_seconds()


def _telegram_clear_session(actor_user_id):
    telegram_auth_sessions.pop(str(actor_user_id or ''), None)


def _telegram_audit_log(actor_user_id, action, details=None):
    details_text = (details or '').strip()
    line = f"🔐 [AUDIT] {action} | by={actor_user_id}"
    if details_text:
        line += f" | {details_text}"
    app.logger.info(line)
    audit_chat_id = (os.environ.get('TELEGRAM_AUDIT_CHAT_ID') or os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    if audit_chat_id:
        telegram_send_message_to_chat(audit_chat_id, line, disable_notification=True)


def _to_positive_int(text):
    try:
        value = int(str(text).strip())
        return value if value > 0 else None
    except Exception:
        return None


def _action_rate_limited(action_key, max_calls, window_seconds):
    now = time.time()
    actor_key = f"ip:{request.remote_addr or 'unknown'}"
    if current_user.is_authenticated:
        actor_key = f"user:{current_user.id}"
    bucket_key = f"{action_key}:{actor_key}"
    with action_rate_limit_lock:
        bucket = action_rate_limit_buckets.get(bucket_key, [])
        bucket = [t for t in bucket if t > now - window_seconds]
        if len(bucket) >= max_calls:
            action_rate_limit_buckets[bucket_key] = bucket
            return True
        bucket.append(now)
        action_rate_limit_buckets[bucket_key] = bucket
    return False


def _posts_quick_lines(limit=10):
    posts = Post.query.order_by(Post.id.desc()).limit(limit).all()
    if not posts:
        return ["📝 Posts: none"]
    lines = [f"📝 Latest posts ({len(posts)}):"]
    for post in posts:
        status = "✅ published" if post.is_published else "🕓 draft"
        lines.append(f"- #{post.id} {post.title[:45]} ({status})")
    return lines


def _comments_quick_lines(limit=10):
    comments = Comment.query.order_by(Comment.id.desc()).limit(limit).all()
    if not comments:
        return ["💬 Comments: none"]
    lines = [f"💬 Latest comments ({len(comments)}):"]
    for comment in comments:
        preview = (comment.get_decrypted_content() if hasattr(comment, 'get_decrypted_content') else comment.content) if comment.content else ""
        preview = (preview or "").replace('\n', ' ').strip()
        if len(preview) > 50:
            preview = preview[:47] + "..."
        lines.append(f"- #{comment.id} by user_id={comment.author_id or 'unknown'}: {preview}")
    return lines


def _human_uptime(seconds):
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _build_page_nav(kind, offset, page_size, total_count):
    prev_offset = max(0, offset - page_size)
    next_offset = offset + page_size
    has_prev = offset > 0
    has_next = next_offset < total_count
    nav_row = []
    if has_prev:
        nav_row.append({"text": "⬅️ Prev", "callback_data": f"nav:{kind}:{prev_offset}"})
    if has_next:
        nav_row.append({"text": "Next ➡️", "callback_data": f"nav:{kind}:{next_offset}"})
    return nav_row


def _posts_page_payload(offset=0, page_size=6):
    total_count = Post.query.count()
    posts = Post.query.order_by(Post.id.desc()).offset(max(0, offset)).limit(page_size).all()
    lines = [f"📝 Posts ({total_count}) | offset={max(0, offset)}"]
    if not posts:
        lines.append("No posts found.")
    for post in posts:
        status = "✅ published" if post.is_published else "🕓 draft"
        lines.append(f"- #{post.id} {post.title[:42]} ({status})")
    return lines, posts, total_count


def _users_page_payload(offset=0, page_size=8):
    base_query = User.query.filter_by(is_admin=False).order_by(User.username.asc())
    total_count = base_query.count()
    users = base_query.offset(max(0, offset)).limit(page_size).all()
    lines = [f"👥 Users ({total_count}) | offset={max(0, offset)}"]
    if not users:
        lines.append("No users found.")
    for user in users:
        role = "admin" if user.is_admin else "user"
        lines.append(f"- #{user.id} @{user.username} ({role})")
    return lines, users, total_count


def _comments_page_payload(offset=0, page_size=8):
    total_count = Comment.query.count()
    comments = Comment.query.order_by(Comment.id.desc()).offset(max(0, offset)).limit(page_size).all()
    lines = [f"💬 Comments ({total_count}) | offset={max(0, offset)}"]
    if not comments:
        lines.append("No comments found.")
    for comment in comments:
        preview = (comment.content or "").replace("\n", " ").strip()
        if len(preview) > 45:
            preview = preview[:42] + "..."
        lines.append(f"- #{comment.id} by user_id={comment.author_id or 'n/a'}: {preview or '(empty)'}")
    return lines, comments, total_count


def _posts_inline_markup(posts, offset, total_count, page_size):
    rows = []
    for post in posts[:5]:
        rows.append([
            {"text": f"✅ Pub #{post.id}", "callback_data": f"post_pub:{post.id}"},
            {"text": f"🗑️ Del #{post.id}", "callback_data": f"post_del:{post.id}"}
        ])
    nav_row = _build_page_nav("posts", offset, page_size, total_count)
    if nav_row:
        rows.append(nav_row)
    rows.append([{"text": "🏠 Main menu", "callback_data": "nav:menu:0"}])
    return {"inline_keyboard": rows}


def _users_inline_markup(users, offset, total_count, page_size):
    rows = []
    for user in users[:5]:
        rows.append([
            {"text": f"⬆️ #{user.id}", "callback_data": f"user_prom:{user.id}"},
            {"text": f"⬇️ #{user.id}", "callback_data": f"user_dem:{user.id}"},
            {"text": f"🗑️ #{user.id}", "callback_data": f"user_del:{user.id}"}
        ])
    nav_row = _build_page_nav("users", offset, page_size, total_count)
    if nav_row:
        rows.append(nav_row)
    rows.append([{"text": "🏠 Main menu", "callback_data": "nav:menu:0"}])
    return {"inline_keyboard": rows}


def _comments_inline_markup(comments, offset, total_count, page_size):
    rows = []
    for comment in comments[:6]:
        rows.append([{"text": f"🗑️ Delete #{comment.id}", "callback_data": f"comment_del:{comment.id}"}])
    nav_row = _build_page_nav("comments", offset, page_size, total_count)
    if nav_row:
        rows.append(nav_row)
    rows.append([{"text": "🏠 Main menu", "callback_data": "nav:menu:0"}])
    return {"inline_keyboard": rows}


def telegram_send_posts_page(offset=0, page_size=6):
    lines, posts, total_count = _posts_page_payload(offset=offset, page_size=page_size)
    return telegram_send_message(
        "\n".join(lines),
        reply_markup=_posts_inline_markup(posts, max(0, offset), total_count, page_size)
    )


def telegram_send_users_page(offset=0, page_size=8):
    lines, users, total_count = _users_page_payload(offset=offset, page_size=page_size)
    return telegram_send_message(
        "\n".join(lines),
        reply_markup=_users_inline_markup(users, max(0, offset), total_count, page_size)
    )


def telegram_send_comments_page(offset=0, page_size=8):
    lines, comments, total_count = _comments_page_payload(offset=offset, page_size=page_size)
    return telegram_send_message(
        "\n".join(lines),
        reply_markup=_comments_inline_markup(comments, max(0, offset), total_count, page_size)
    )


def telegram_posts_menu_markup():
    return {
        "keyboard": [
            ["📋 List posts", "➕ New post"],
            ["✅ Publish post", "🗑️ Delete post"],
            ["🏠 Main menu"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def telegram_users_menu_markup():
    return {
        "keyboard": [
            ["📋 List users", "⬆️ Promote user"],
            ["⬇️ Demote user", "🗑️ Delete user"],
            ["🏠 Main menu"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def telegram_comments_menu_markup():
    return {
        "keyboard": [
            ["📋 List comments", "🗑️ Delete comment"],
            ["🏠 Main menu"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def telegram_messages_menu_markup():
    return {
        "keyboard": [
            ["📋 Full list", "👥 All users"],
            ["📨 Sent users", "⏳ Pending users"],
            ["💬 Reply helper", "⚡ Reply last"],
            ["❌ Cancel reply", "🏠 Main menu"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def telegram_confirm_menu_markup():
    return {
        "keyboard": [
            ["✅ Confirm", "❌ Cancel"],
            ["🏠 Main menu"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def parse_basic_auth():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        return None, None

    encoded_credentials = auth_header.split(' ', 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded.split(':', 1)
        return username, password
    except Exception:
        return None, None


def authenticate_admin_api():
    username, password = parse_basic_auth()
    if not username or not password:
        return None

    user = User.query.filter_by(username=username, is_admin=True).first()
    if not user:
        return None

    if not bcrypt.check_password_hash(user.password, password):
        return None

    return user


def admin_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_user = authenticate_admin_api()
        if not admin_user:
            return (
                jsonify({'error': 'Authentication required for admin mobile API.'}),
                401,
                {'WWW-Authenticate': 'Basic realm="Admin Mobile API"'}
            )

        request.admin_api_user = admin_user
        return f(*args, **kwargs)

    return decorated_function


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


def telegram_is_enabled():
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    chat_id = (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    return bool(token and chat_id)


def telegram_main_menu_markup():
    return {
        "keyboard": [
            ["📝 Posts", "👥 Users"],
            ["💬 Comments", "📨 Messages"],
            ["📊 Status", "⚡ Reply last"],
            ["ℹ️ Help", "🔎 Search"],
            ["❌ Cancel reply"]
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False
    }


def telegram_send_message_to_chat(chat_id, text, disable_notification=False, reply_markup=None):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': text
    }
    if disable_notification:
        payload['disable_notification'] = True
    if reply_markup is not None:
        payload['reply_markup'] = json.dumps(reply_markup)

    try:
        response = requests.post(url, data=payload, timeout=10)
        data = response.json()
        if not data.get('ok'):
            app.logger.warning("Telegram sendMessage failed: %s", data)
        return bool(data.get('ok'))
    except Exception:
        app.logger.exception("Telegram sendMessage exception")
        return False


def telegram_send_message(text, disable_notification=False, reply_markup=None):
    chat_id = (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    return telegram_send_message_to_chat(
        chat_id,
        text,
        disable_notification=disable_notification,
        reply_markup=reply_markup
    )


def _project_root():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def _absolute_upload_path(stored_path):
    if not stored_path:
        return None
    if os.path.isabs(stored_path):
        return stored_path
    return os.path.join(_project_root(), stored_path)


def telegram_send_photo(chat_id, file_path, caption=None, reply_markup=None):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token or not chat_id:
        return False

    absolute_path = _absolute_upload_path(file_path)
    if not absolute_path or not os.path.exists(absolute_path):
        return False

    url = f"https://api.telegram.org/bot{token}/sendPhoto"
    data = {'chat_id': chat_id}
    if caption:
        data['caption'] = caption
    if reply_markup is not None:
        data['reply_markup'] = json.dumps(reply_markup)

    try:
        with open(absolute_path, 'rb') as image_file:
            response = requests.post(url, data=data, files={'photo': image_file}, timeout=20)
        result = response.json()
        if not result.get('ok'):
            app.logger.warning("Telegram sendPhoto failed: %s", result)
        return bool(result.get('ok'))
    except Exception:
        app.logger.exception("Telegram sendPhoto exception")
        return False


def telegram_send_document(chat_id, file_path, caption=None, reply_markup=None):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token or not chat_id:
        return False

    absolute_path = _absolute_upload_path(file_path)
    if not absolute_path or not os.path.exists(absolute_path):
        return False

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    data = {'chat_id': chat_id}
    if caption:
        data['caption'] = caption
    if reply_markup is not None:
        data['reply_markup'] = json.dumps(reply_markup)

    try:
        with open(absolute_path, 'rb') as file_obj:
            response = requests.post(url, data=data, files={'document': file_obj}, timeout=20)
        result = response.json()
        if not result.get('ok'):
            app.logger.warning("Telegram sendDocument failed: %s", result)
        return bool(result.get('ok'))
    except Exception:
        app.logger.exception("Telegram sendDocument exception")
        return False


def telegram_get_file_path(file_id):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token or not file_id:
        return None

    url = f"https://api.telegram.org/bot{token}/getFile"
    try:
        response = requests.get(url, params={'file_id': file_id}, timeout=10)
        data = response.json()
        if not data.get('ok'):
            app.logger.warning("Telegram getFile failed: %s", data)
            return None
        return data.get('result', {}).get('file_path')
    except Exception:
        app.logger.exception("Telegram getFile exception")
        return None


def telegram_download_file_to_uploads(file_id, preferred_ext='jpg'):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token:
        return None

    remote_file_path = telegram_get_file_path(file_id)
    if not remote_file_path:
        return None

    ext = os.path.splitext(remote_file_path)[1].lower().strip('.')
    if not ext:
        ext = preferred_ext
    if len(ext) > 8:
        ext = preferred_ext

    filename = f"tg_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:10]}.{ext}"
    relative_path = os.path.join('uploads', filename)
    absolute_path = _absolute_upload_path(relative_path)
    os.makedirs(os.path.dirname(absolute_path), exist_ok=True)

    file_url = f"https://api.telegram.org/file/bot{token}/{remote_file_path}"
    try:
        response = requests.get(file_url, timeout=20)
        response.raise_for_status()
        with open(absolute_path, 'wb') as output_file:
            output_file.write(response.content)
        return relative_path
    except Exception:
        app.logger.exception("Telegram file download exception")
        return None


def telegram_answer_callback_query(callback_query_id, text=None):
    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token or not callback_query_id:
        return False

    url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
    payload = {'callback_query_id': callback_query_id}
    if text:
        payload['text'] = text
    try:
        response = requests.post(url, data=payload, timeout=10)
        data = response.json()
        return bool(data.get('ok'))
    except Exception:
        app.logger.exception("Telegram answerCallbackQuery exception")
        return False


def telegram_inline_reply_markup(target_user_id):
    return {
        "inline_keyboard": [
            [
                {"text": "💬 Reply", "callback_data": f"reply_to:{target_user_id}"}
            ]
        ]
    }


def notify_admin_telegram_new_message(message):
    """Send website -> Telegram notification for admin."""
    if not telegram_is_enabled():
        return
    if not message or not message.sender or message.sender.is_admin:
        return

    text_preview = (message.get_decrypted_content() if message.is_encrypted else message.content) or ''
    text_preview = text_preview.strip()
    if len(text_preview) > 250:
        text_preview = text_preview[:247] + '...'

    if message.file_path and not text_preview:
        text_preview = f"[{message.file_type or 'file'} attachment]"

    caption = (
        f"📩 From @{message.sender.username} (user_id={message.sender_id})\n"
        f"📝 {text_preview if text_preview else '(no text)'}\n"
        f"👇 Tap Reply to answer directly."
    )

    sent = False
    if message.file_path:
        if message.file_type == 'image':
            sent = telegram_send_photo(
                (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip(),
                message.file_path,
                caption=caption,
                reply_markup=telegram_inline_reply_markup(message.sender_id)
            )
        else:
            sent = telegram_send_document(
                (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip(),
                message.file_path,
                caption=caption,
                reply_markup=telegram_inline_reply_markup(message.sender_id)
            )

    if not sent:
        notification_text = (
            f"📩 New message from @{message.sender.username} (user_id={message.sender_id})\n\n"
            f"📝 {text_preview}\n\n"
            f"👇 Tap Reply to answer directly."
        )
        telegram_send_message(
            notification_text,
            reply_markup=telegram_inline_reply_markup(message.sender_id)
        )


def parse_telegram_reply_command(text):
    match = re.match(r'^/reply(?:@[A-Za-z0-9_]+)?\s+(\S+)(?:\s+(.+))?$', text.strip(), re.DOTALL)
    if not match:
        return None, None
    target = match.group(1).strip()
    message = match.group(2).strip() if match.group(2) else None
    return target, message


def resolve_blog_user_reference(user_ref):
    """Resolve /reply target by user_id or @username."""
    if not user_ref:
        return None

    normalized = user_ref.strip()
    if normalized.startswith('@'):
        normalized = normalized[1:]

    if normalized.isdigit():
        return User.query.filter_by(id=int(normalized), is_admin=False).first()

    return User.query.filter_by(username=normalized, is_admin=False).first()


def get_most_recent_pending_user(admin_user_id):
    pending_users = _blog_users_pending_reply(admin_user_id)
    if not pending_users:
        return None

    best_user = None
    best_message_id = -1
    for user in pending_users:
        latest_user_message = Message.query.filter(
            Message.sender_id == user.id,
            Message.receiver_id == admin_user_id
        ).order_by(Message.id.desc()).first()
        if latest_user_message and latest_user_message.id > best_message_id:
            best_message_id = latest_user_message.id
            best_user = user

    return best_user


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


def process_telegram_callback_query(callback_query):
    configured_chat_id = (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    if not configured_chat_id:
        return False

    callback_id = callback_query.get('id')
    callback_data = (callback_query.get('data') or '').strip()
    callback_message = callback_query.get('message') or {}
    callback_chat_id = str((callback_message.get('chat') or {}).get('id', ''))
    callback_actor_id = str((callback_query.get('from') or {}).get('id', ''))

    if callback_chat_id != configured_chat_id:
        telegram_answer_callback_query(callback_id, "Not authorized")
        return False
    if not _telegram_is_actor_authorized(callback_actor_id):
        telegram_answer_callback_query(callback_id, "Admin access denied")
        return False
    if _telegram_pin_required() and not _telegram_is_session_valid(callback_actor_id):
        _telegram_set_admin_state(callback_chat_id, "await_pin", actor_user_id=callback_actor_id)
        telegram_answer_callback_query(callback_id, "Session expired")
        telegram_send_message("🔒 Session expired. Send your admin PIN to continue.")
        return False
    _telegram_start_session(callback_actor_id)

    if callback_data.startswith('nav:'):
        _, section, raw_offset = (callback_data.split(':', 2) + ['0', '0'])[:3]
        offset = _to_positive_int(raw_offset)
        offset = 0 if offset is None else offset
        if section == 'menu':
            telegram_answer_callback_query(callback_id, "Main menu")
            telegram_send_message("🤖 Admin control panel", reply_markup=telegram_main_menu_markup())
            return True
        if section == 'posts':
            telegram_answer_callback_query(callback_id, "Posts page")
            telegram_send_posts_page(offset=offset)
            return True
        if section == 'users':
            telegram_answer_callback_query(callback_id, "Users page")
            telegram_send_users_page(offset=offset)
            return True
        if section == 'comments':
            telegram_answer_callback_query(callback_id, "Comments page")
            telegram_send_comments_page(offset=offset)
            return True

    if callback_data.startswith('post_pub:'):
        post_id = _to_positive_int(callback_data.split(':', 1)[1])
        post = Post.query.get(post_id) if post_id else None
        if not post:
            telegram_answer_callback_query(callback_id, "Post not found")
            return False
        post.is_published = True
        post.is_draft = False
        post.scheduled_date = post.scheduled_date or datetime.utcnow()
        db.session.commit()
        _telegram_audit_log(callback_actor_id, "publish_post", f"post_id={post.id} via=inline")
        telegram_answer_callback_query(callback_id, f"Published #{post.id}")
        telegram_send_message(f"✅ Post #{post.id} published.")
        return True

    if callback_data.startswith('post_del:'):
        post_id = _to_positive_int(callback_data.split(':', 1)[1])
        post = Post.query.get(post_id) if post_id else None
        if not post:
            telegram_answer_callback_query(callback_id, "Post not found")
            return False
        _telegram_set_admin_state(
            callback_chat_id,
            "confirm_delete_post",
            post_id=post.id,
            post_title=post.title[:80]
        )
        telegram_answer_callback_query(callback_id, f"Confirm delete #{post.id}")
        telegram_send_message(
            f"⚠️ Confirm deletion of post #{post.id}: {post.title[:80]}",
            reply_markup=telegram_confirm_menu_markup()
        )
        return True

    if callback_data.startswith('user_prom:'):
        user_id = _to_positive_int(callback_data.split(':', 1)[1])
        user = User.query.get(user_id) if user_id else None
        if not user:
            telegram_answer_callback_query(callback_id, "User not found")
            return False
        user.is_admin = True
        db.session.commit()
        _telegram_audit_log(callback_actor_id, "promote_user", f"user_id={user.id} via=inline")
        telegram_answer_callback_query(callback_id, f"Promoted #{user.id}")
        telegram_send_message(f"⬆️ User @{user.username} promoted.")
        return True

    if callback_data.startswith('user_dem:'):
        user_id = _to_positive_int(callback_data.split(':', 1)[1])
        user = User.query.get(user_id) if user_id else None
        if not user:
            telegram_answer_callback_query(callback_id, "User not found")
            return False
        if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
            telegram_answer_callback_query(callback_id, "Blocked")
            telegram_send_message("🛡️ Blocked: cannot demote the last admin.")
            return False
        user.is_admin = False
        db.session.commit()
        _telegram_audit_log(callback_actor_id, "demote_user", f"user_id={user.id} via=inline")
        telegram_answer_callback_query(callback_id, f"Demoted #{user.id}")
        telegram_send_message(f"⬇️ User @{user.username} demoted.")
        return True

    if callback_data.startswith('user_del:'):
        user_id = _to_positive_int(callback_data.split(':', 1)[1])
        user = User.query.get(user_id) if user_id else None
        if not user:
            telegram_answer_callback_query(callback_id, "User not found")
            return False
        _telegram_set_admin_state(
            callback_chat_id,
            "confirm_delete_user",
            user_id=user.id,
            username=(user.username or '')[:80]
        )
        telegram_answer_callback_query(callback_id, f"Confirm delete #{user.id}")
        telegram_send_message(
            f"⚠️ Confirm deletion of user @{(user.username or 'unknown')[:80]} (id={user.id})\n"
            f"Type exactly: ✅ Confirm {user.id}",
            reply_markup=telegram_confirm_menu_markup()
        )
        return True

    if callback_data.startswith('comment_del:'):
        comment_id = _to_positive_int(callback_data.split(':', 1)[1])
        comment = Comment.query.get(comment_id) if comment_id else None
        if not comment:
            telegram_answer_callback_query(callback_id, "Comment not found")
            return False
        preview = (comment.content or '').replace('\n', ' ').strip()
        if len(preview) > 80:
            preview = preview[:77] + "..."
        _telegram_set_admin_state(
            callback_chat_id,
            "confirm_delete_comment",
            comment_id=comment.id,
            preview=preview
        )
        telegram_answer_callback_query(callback_id, f"Confirm delete #{comment.id}")
        telegram_send_message(
            f"⚠️ Confirm deletion of comment #{comment.id}:\n{preview or '(empty)'}",
            reply_markup=telegram_confirm_menu_markup()
        )
        return True

    if callback_data.startswith('reply_to:'):
        try:
            target_user_id = int(callback_data.split(':', 1)[1])
        except Exception:
            telegram_answer_callback_query(callback_id, "Invalid target")
            return False

        target_user = User.query.filter_by(id=target_user_id, is_admin=False).first()
        if not target_user:
            telegram_answer_callback_query(callback_id, "Unknown user")
            telegram_send_message("❌ Unknown target user.", disable_notification=True)
            return False

        telegram_reply_state[callback_chat_id] = target_user.id
        _telegram_clear_admin_state(callback_chat_id)
        _telegram_start_session(callback_actor_id)
        telegram_answer_callback_query(callback_id, f"Replying to @{target_user.username}")
        telegram_send_message(
            f"💬 Reply mode enabled for @{target_user.username} (id={target_user.id}).\n"
            f"✍️ Send your message now.\n"
            f"❌ Use /cancel to stop.",
            reply_markup=telegram_main_menu_markup()
        )
        return True

    telegram_answer_callback_query(callback_id)
    return False


def process_telegram_update_message(message_data):
    configured_chat_id = (os.environ.get('TELEGRAM_ADMIN_CHAT_ID') or '').strip()
    incoming_chat_id = str(message_data.get('chat', {}).get('id', ''))
    if not configured_chat_id:
        return False

    from_user = message_data.get('from') or {}
    incoming_actor_id = str(from_user.get('id', ''))
    incoming_username = from_user.get('username') or ''
    incoming_first_name = from_user.get('first_name') or ''
    incoming_text = (message_data.get('text') or '').strip()
    incoming_caption = (message_data.get('caption') or '').strip()
    incoming_photos = message_data.get('photo') or []
    incoming_document = message_data.get('document') or {}

    if incoming_chat_id:
        # Track all users who contacted the bot (/start or normal message)
        has_pending = bool(incoming_text and not incoming_text.lower().startswith('/start'))
        tracked_last_message = incoming_text if incoming_text else (incoming_caption if incoming_caption else None)
        try:
            parsed_chat_id = int(incoming_chat_id)
            _telegram_users_upsert(
                chat_id=parsed_chat_id,
                username=incoming_username,
                first_name=incoming_first_name,
                has_pending=has_pending,
                last_message=tracked_last_message
            )
        except ValueError:
            pass

    # Non-admin chats are tracked only; no bridge command expected
    if incoming_chat_id != configured_chat_id:
        return False

    has_media = bool(incoming_photos or incoming_document)
    if not incoming_text and not has_media:
        return False

    command_token = ''
    command_parts = []
    if incoming_text and incoming_text.startswith('/'):
        command_token = incoming_text.split()[0].lower()
        if '@' in command_token:
            command_token = command_token.split('@', 1)[0]
        command_parts = incoming_text.strip().split(maxsplit=2)

    admin_state = _telegram_get_admin_state(incoming_chat_id)
    pin = (os.environ.get('TELEGRAM_ADMIN_PIN') or '').strip()

    if command_token == '/start':
        if not _telegram_is_actor_authorized(incoming_actor_id):
            telegram_send_message("⛔ Access denied for this Telegram account.")
            return False
        if _telegram_pin_required() and not _telegram_is_session_valid(incoming_actor_id):
            _telegram_set_admin_state(incoming_chat_id, "await_pin", actor_user_id=incoming_actor_id)
            telegram_send_message("🔒 Enter admin PIN to unlock the control panel.")
            return False
        _telegram_start_session(incoming_actor_id)

    if not _telegram_is_actor_authorized(incoming_actor_id):
        if incoming_text:
            telegram_send_message("⛔ Access denied for this Telegram account.")
        return False

    if _telegram_pin_required() and not _telegram_is_session_valid(incoming_actor_id):
        if command_token == '/cancel':
            _telegram_clear_admin_state(incoming_chat_id)
            _telegram_clear_session(incoming_actor_id)
            telegram_send_message("❌ Session auth cancelled.")
            return False
        if (
            admin_state
            and admin_state.get('mode') == 'await_pin'
            and str(admin_state.get('actor_user_id', '')) == incoming_actor_id
            and incoming_text
            and not command_token.startswith('/')
        ):
            if incoming_text.strip() == pin:
                _telegram_clear_admin_state(incoming_chat_id)
                _telegram_start_session(incoming_actor_id)
                telegram_send_message("✅ PIN accepted. Control panel unlocked.", reply_markup=telegram_main_menu_markup())
            else:
                telegram_send_message("❌ Wrong PIN. Try again or use /cancel.")
            return False
        _telegram_set_admin_state(incoming_chat_id, "await_pin", actor_user_id=incoming_actor_id)
        telegram_send_message("🔒 Session locked. Send your admin PIN.")
        return False

    _telegram_start_session(incoming_actor_id)

    admin_user = _bridge_admin_user()
    admin_user_id = admin_user.id if admin_user else None

    # ----- Friendly button menu handlers -----
    if incoming_text in ("🏠 Main menu", "/menu", "/panel"):
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message(
            "🤖 Admin control panel\nChoose a section:",
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if incoming_text == "ℹ️ Help":
        telegram_send_message(
            "🧭 Blog control commands:\n"
            "📝 Posts, 👥 Users, 💬 Comments, 📨 Messages\n"
            "You can use buttons or slash commands.\n"
            "Examples:\n"
            "/posts [page], /users [page], /comments [page]\n"
            "/finduser <query>, /findpost <query>\n"
            "/status\n"
            "/reply 12 hello\n"
            "Type /menu anytime.",
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if incoming_text == "📊 Status" or command_token == '/status':
        total_users = User.query.count()
        non_admin_users = User.query.filter_by(is_admin=False).count()
        total_posts = Post.query.count()
        draft_posts = Post.query.filter_by(is_draft=True).count()
        total_comments = Comment.query.count()
        pending_users = len(_blog_users_pending_reply(admin_user_id))
        uptime = _human_uptime(time.time() - telegram_process_started_at)
        telegram_send_message(
            "📊 MyBlog status\n"
            f"👥 users: {total_users} (non-admin: {non_admin_users})\n"
            f"📝 posts: {total_posts} (drafts: {draft_posts})\n"
            f"💬 comments: {total_comments}\n"
            f"⏳ pending chats: {pending_users}\n"
            f"⏱️ bot uptime: {uptime}",
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if incoming_text == "🔎 Search":
        _telegram_set_admin_state(incoming_chat_id, "await_search_query")
        telegram_send_message("🔎 Send query.\nExamples:\nfind user john\nfind post privacy")
        return False

    if incoming_text == "📝 Posts":
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message("📝 Posts menu", reply_markup=telegram_posts_menu_markup())
        return False

    if incoming_text == "👥 Users":
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message("👥 Users menu", reply_markup=telegram_users_menu_markup())
        return False

    if incoming_text == "💬 Comments":
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message("💬 Comments menu", reply_markup=telegram_comments_menu_markup())
        return False

    if incoming_text == "📨 Messages":
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message("📨 Messages menu", reply_markup=telegram_messages_menu_markup())
        return False

    if incoming_text == "📋 List posts" or command_token == '/posts':
        page = _to_positive_int(command_parts[1]) if len(command_parts) > 1 else 1
        offset = max(0, ((page or 1) - 1) * 6)
        telegram_send_posts_page(offset=offset, page_size=6)
        return False

    if incoming_text == "📋 List users":
        telegram_send_users_page(offset=0, page_size=8)
        return False

    if incoming_text == "📋 List comments" or command_token == '/comments':
        page = _to_positive_int(command_parts[1]) if len(command_parts) > 1 else 1
        offset = max(0, ((page or 1) - 1) * 8)
        telegram_send_comments_page(offset=offset, page_size=8)
        return False

    if incoming_text == "➕ New post":
        _telegram_set_admin_state(incoming_chat_id, "await_new_post_title")
        telegram_send_message("➕ Send the new post title:", reply_markup=telegram_posts_menu_markup())
        return False

    if incoming_text == "✅ Publish post":
        _telegram_set_admin_state(incoming_chat_id, "await_publish_post_id")
        telegram_send_message("✅ Send the post ID to publish:", reply_markup=telegram_posts_menu_markup())
        return False

    if incoming_text == "🗑️ Delete post":
        _telegram_set_admin_state(incoming_chat_id, "await_delete_post_id")
        telegram_send_message("🗑️ Send the post ID to delete:", reply_markup=telegram_posts_menu_markup())
        return False

    if incoming_text == "⬆️ Promote user":
        _telegram_set_admin_state(incoming_chat_id, "await_promote_user_id")
        telegram_send_message("⬆️ Send the user ID to promote:", reply_markup=telegram_users_menu_markup())
        return False

    if incoming_text == "⬇️ Demote user":
        _telegram_set_admin_state(incoming_chat_id, "await_demote_user_id")
        telegram_send_message("⬇️ Send the user ID to demote:", reply_markup=telegram_users_menu_markup())
        return False

    if incoming_text == "🗑️ Delete user":
        _telegram_set_admin_state(incoming_chat_id, "await_delete_user_id")
        telegram_send_message("🗑️ Send the user ID to delete:", reply_markup=telegram_users_menu_markup())
        return False

    if incoming_text == "🗑️ Delete comment":
        _telegram_set_admin_state(incoming_chat_id, "await_delete_comment_id")
        telegram_send_message("🗑️ Send the comment ID to delete:", reply_markup=telegram_comments_menu_markup())
        return False

    if incoming_text == "📋 Full list":
        all_users = _blog_non_admin_users()
        users_with_messages = _blog_users_with_messages(admin_user_id)
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        lines = []
        lines.extend(_format_blog_users_lines("👥 All blog users", all_users))
        lines.append("")
        lines.extend(_format_blog_users_lines("📨 Users who sent messages", users_with_messages))
        lines.append("")
        lines.extend(_format_blog_users_lines("⏳ Pending (not replied/seen yet)", users_pending_reply))
        telegram_send_message("\n".join(lines), reply_markup=telegram_messages_menu_markup())
        return False

    if incoming_text == "👥 All users":
        all_users = _blog_non_admin_users()
        telegram_send_message(
            "\n".join(_format_blog_users_lines("👥 All blog users", all_users)),
            reply_markup=telegram_messages_menu_markup()
        )
        return False

    if incoming_text == "📨 Sent users":
        users_with_messages = _blog_users_with_messages(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("📨 Users who sent messages", users_with_messages)),
            reply_markup=telegram_messages_menu_markup()
        )
        return False

    if incoming_text == "⏳ Pending users":
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("⏳ Pending (not replied/seen yet)", users_pending_reply)),
            reply_markup=telegram_messages_menu_markup()
        )
        return False

    if incoming_text == "💬 Reply helper":
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        lines = [
            "💬 Reply helper:",
            "1) Send: /reply <user_id_or_username>",
            "2) Then send your message",
            "",
            "⏳ Pending users:"
        ]
        lines.extend(_format_blog_users_lines("Pending", users_pending_reply))
        telegram_send_message("\n".join(lines), reply_markup=telegram_messages_menu_markup())
        return False

    if incoming_text == "⚡ Reply last":
        _telegram_set_admin_state(incoming_chat_id, "await_replylast_text")
        telegram_send_message("⚡ Send the message text for the most recent pending user.")
        return False

    if incoming_text in ("❌ Cancel reply", "❌ Cancel"):
        command_token = '/cancel'

    # ----- Stateful admin actions for post/user/comment management -----
    if admin_state and not command_token.startswith('/'):
        mode = admin_state.get('mode')

        if mode == "await_search_query":
            query = (incoming_text or "").strip()
            normalized = query.lower()
            if normalized.startswith('find user '):
                normalized = normalized[len('find user '):].strip()
                users = User.query.filter(User.username.ilike(f"%{normalized}%")).order_by(User.username.asc()).limit(20).all() if normalized else []
                lines = [f"🔎 Users matching '{normalized}':"]
                if not users:
                    lines.append("No matches.")
                for user in users:
                    lines.append(f"- #{user.id} @{user.username}")
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("\n".join(lines), reply_markup=telegram_users_menu_markup())
                return False
            if normalized.startswith('find post '):
                normalized = normalized[len('find post '):].strip()
                posts = Post.query.filter(Post.title.ilike(f"%{normalized}%")).order_by(Post.id.desc()).limit(20).all() if normalized else []
                lines = [f"🔎 Posts matching '{normalized}':"]
                if not posts:
                    lines.append("No matches.")
                for post in posts:
                    status = "published" if post.is_published else "draft"
                    lines.append(f"- #{post.id} {post.title[:48]} ({status})")
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("\n".join(lines), reply_markup=telegram_posts_menu_markup())
                return False
            telegram_send_message("Use: find user <text> OR find post <text>")
            return False

        if mode == "await_new_post_title":
            title = incoming_text.strip()
            if not title:
                telegram_send_message("❌ Title cannot be empty. Send the title again.")
                return False
            _telegram_set_admin_state(incoming_chat_id, "await_new_post_content", title=title)
            telegram_send_message("✍️ Great. Now send the post content.")
            return False

        if mode == "await_new_post_content":
            content = incoming_text.strip()
            title = admin_state.get('title', '').strip()
            if not content or not title:
                telegram_send_message("❌ Content cannot be empty. Send content again.")
                return False
            if not admin_user:
                telegram_send_message("❌ No sender account found on the blog.")
                return False
            post = Post(
                title=title,
                content=content,
                author_id=admin_user.id,
                is_published=False,
                is_draft=True,
                scheduled_date=datetime.utcnow()
            )
            db.session.add(post)
            db.session.commit()
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(
                f"✅ Draft created: #{post.id} {post.title}\nUse '✅ Publish post' when ready.",
                reply_markup=telegram_posts_menu_markup()
            )
            return False

        if mode == "await_publish_post_id":
            post_id = _to_positive_int(incoming_text)
            post = Post.query.get(post_id) if post_id else None
            if not post:
                telegram_send_message("❌ Invalid post ID. Try again.")
                return False
            post.is_published = True
            post.is_draft = False
            post.scheduled_date = post.scheduled_date or datetime.utcnow()
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "publish_post", f"post_id={post.id}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"✅ Post #{post.id} published.", reply_markup=telegram_posts_menu_markup())
            return False

        if mode == "await_delete_post_id":
            post_id = _to_positive_int(incoming_text)
            post = Post.query.get(post_id) if post_id else None
            if not post:
                telegram_send_message("❌ Invalid post ID. Try again.")
                return False
            _telegram_set_admin_state(
                incoming_chat_id,
                "confirm_delete_post",
                post_id=post.id,
                post_title=post.title[:80]
            )
            telegram_send_message(
                f"⚠️ Confirm deletion of post #{post.id}: {post.title[:80]}",
                reply_markup=telegram_confirm_menu_markup()
            )
            return False

        if mode == "await_promote_user_id":
            user_id = _to_positive_int(incoming_text)
            user = User.query.get(user_id) if user_id else None
            if not user:
                telegram_send_message("❌ Invalid user ID. Try again.")
                return False
            user.is_admin = True
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "promote_user", f"user_id={user.id}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"⬆️ User @{user.username} promoted.", reply_markup=telegram_users_menu_markup())
            return False

        if mode == "await_demote_user_id":
            user_id = _to_positive_int(incoming_text)
            user = User.query.get(user_id) if user_id else None
            if not user:
                telegram_send_message("❌ Invalid user ID. Try again.")
                return False
            if user.is_admin:
                admin_count = User.query.filter_by(is_admin=True).count()
                if admin_count <= 1:
                    telegram_send_message("🛡️ Blocked: cannot demote the last admin.")
                    return False
            user.is_admin = False
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "demote_user", f"user_id={user.id}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"⬇️ User @{user.username} demoted.", reply_markup=telegram_users_menu_markup())
            return False

        if mode == "await_delete_user_id":
            user_id = _to_positive_int(incoming_text)
            user = User.query.get(user_id) if user_id else None
            if not user:
                telegram_send_message("❌ Invalid user ID. Try again.")
                return False
            _telegram_set_admin_state(
                incoming_chat_id,
                "confirm_delete_user",
                user_id=user.id,
                username=(user.username or '')[:80]
            )
            telegram_send_message(
                f"⚠️ Confirm deletion of user @{(user.username or 'unknown')[:80]} (id={user.id})\n"
                f"Type exactly: ✅ Confirm {user.id}",
                reply_markup=telegram_confirm_menu_markup()
            )
            return False

        if mode == "await_delete_comment_id":
            comment_id = _to_positive_int(incoming_text)
            comment = Comment.query.get(comment_id) if comment_id else None
            if not comment:
                telegram_send_message("❌ Invalid comment ID. Try again.")
                return False
            preview = (comment.content or '').replace('\n', ' ').strip()
            if len(preview) > 80:
                preview = preview[:77] + "..."
            _telegram_set_admin_state(
                incoming_chat_id,
                "confirm_delete_comment",
                comment_id=comment.id,
                preview=preview
            )
            telegram_send_message(
                f"⚠️ Confirm deletion of comment #{comment.id}:\n{preview or '(empty)'}",
                reply_markup=telegram_confirm_menu_markup()
            )
            return False

        if mode == "confirm_delete_post":
            if incoming_text != "✅ Confirm":
                telegram_send_message("⚠️ Press '✅ Confirm' or '❌ Cancel'.", reply_markup=telegram_confirm_menu_markup())
                return False
            post_id = _to_positive_int(admin_state.get('post_id'))
            post = Post.query.get(post_id) if post_id else None
            if not post:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("❌ Post not found anymore.", reply_markup=telegram_posts_menu_markup())
                return False
            post_title = post.title
            db.session.delete(post)
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "delete_post", f"post_id={post_id}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"🗑️ Post deleted: #{post_id} {post_title}", reply_markup=telegram_posts_menu_markup())
            return False

        if mode == "confirm_delete_user":
            expected_user_id = _to_positive_int(admin_state.get('user_id'))
            expected_confirm = f"✅ Confirm {expected_user_id}" if expected_user_id else "✅ Confirm"
            if incoming_text != expected_confirm:
                telegram_send_message(
                    f"⚠️ Type exactly: {expected_confirm}\nOr press ❌ Cancel.",
                    reply_markup=telegram_confirm_menu_markup()
                )
                return False
            user_id = expected_user_id
            user = User.query.get(user_id) if user_id else None
            if not user:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("❌ User not found anymore.", reply_markup=telegram_users_menu_markup())
                return False
            if user.is_admin:
                admin_count = User.query.filter_by(is_admin=True).count()
                if admin_count <= 1:
                    _telegram_clear_admin_state(incoming_chat_id)
                    telegram_send_message("🛡️ Blocked: cannot delete the last admin account.", reply_markup=telegram_users_menu_markup())
                    return False
            username = user.username
            db.session.delete(user)
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "delete_user", f"user_id={user_id} username={username}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"🗑️ User @{username} deleted.", reply_markup=telegram_users_menu_markup())
            return False

        if mode == "confirm_delete_comment":
            if incoming_text != "✅ Confirm":
                telegram_send_message("⚠️ Press '✅ Confirm' or '❌ Cancel'.", reply_markup=telegram_confirm_menu_markup())
                return False
            comment_id = _to_positive_int(admin_state.get('comment_id'))
            comment = Comment.query.get(comment_id) if comment_id else None
            if not comment:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("❌ Comment not found anymore.", reply_markup=telegram_comments_menu_markup())
                return False
            db.session.delete(comment)
            db.session.commit()
            _telegram_audit_log(incoming_actor_id, "delete_comment", f"comment_id={comment_id}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"🗑️ Comment #{comment_id} deleted.", reply_markup=telegram_comments_menu_markup())
            return False

        if mode == "await_replylast_text":
            reply_text = incoming_text.strip()
            if not reply_text:
                telegram_send_message("❌ Message cannot be empty. Send text again.")
                return False
            target_user = get_most_recent_pending_user(admin_user_id)
            if not target_user:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("⏳ No pending users right now.", reply_markup=telegram_messages_menu_markup())
                return False
            if not admin_user:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("❌ No sender account found on the blog.")
                return False
            reply_message = Message(sender_id=admin_user.id, receiver_id=target_user.id)
            reply_message.set_encrypted_content(reply_text)
            db.session.add(reply_message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(reply_message))
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(
                f"✅ Reply sent to @{target_user.username} (user_id={target_user.id}).",
                reply_markup=telegram_messages_menu_markup()
            )
            return True

    if command_token == '/list':
        all_users = _blog_non_admin_users()
        users_with_messages = _blog_users_with_messages(admin_user_id)
        users_pending_reply = _blog_users_pending_reply(admin_user_id)

        lines = []
        lines.extend(_format_blog_users_lines("👥 All blog users", all_users))
        lines.append("")
        lines.extend(_format_blog_users_lines("📨 Users who sent messages", users_with_messages))
        lines.append("")
        lines.extend(_format_blog_users_lines("⏳ Pending (not replied/seen yet)", users_pending_reply))
        lines.append("")
        lines.append("💡 Use: /reply <user_id> <message>")
        telegram_send_message("\n".join(lines), reply_markup=telegram_main_menu_markup())
        return False

    if command_token == '/users':
        page = _to_positive_int(command_parts[1]) if len(command_parts) > 1 else 1
        offset = max(0, ((page or 1) - 1) * 8)
        telegram_send_users_page(offset=offset, page_size=8)
        return False

    if command_token == '/finduser':
        match = re.match(r'^/finduser(?:@[A-Za-z0-9_]+)?\s+(.+)$', incoming_text.strip(), re.IGNORECASE | re.DOTALL)
        query = match.group(1).strip() if match else ''
        users = User.query.filter(User.username.ilike(f"%{query}%")).order_by(User.username.asc()).limit(20).all() if query else []
        lines = [f"🔎 Users matching '{query}':"]
        if not users:
            lines.append("No matches.")
        for user in users:
            lines.append(f"- #{user.id} @{user.username}")
        telegram_send_message("\n".join(lines), reply_markup=telegram_users_menu_markup())
        return False

    if command_token == '/findpost':
        match = re.match(r'^/findpost(?:@[A-Za-z0-9_]+)?\s+(.+)$', incoming_text.strip(), re.IGNORECASE | re.DOTALL)
        query = match.group(1).strip() if match else ''
        posts = Post.query.filter(Post.title.ilike(f"%{query}%")).order_by(Post.id.desc()).limit(20).all() if query else []
        lines = [f"🔎 Posts matching '{query}':"]
        if not posts:
            lines.append("No matches.")
        for post in posts:
            status = "published" if post.is_published else "draft"
            lines.append(f"- #{post.id} {post.title[:48]} ({status})")
        telegram_send_message("\n".join(lines), reply_markup=telegram_posts_menu_markup())
        return False

    if command_token == '/sent':
        users_with_messages = _blog_users_with_messages(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("📨 Users who sent messages", users_with_messages)),
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if command_token == '/pending':
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("⏳ Pending (not replied/seen yet)", users_pending_reply)),
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if command_token == '/replylast':
        match = re.match(r'^/replylast\s+(.+)$', incoming_text.strip(), re.DOTALL | re.IGNORECASE)
        if not match:
            telegram_send_message("Invalid format.\nUse: /replylast <message>", disable_notification=True)
            return False

        reply_text = match.group(1).strip()
        if not reply_text:
            telegram_send_message("Message cannot be empty.", disable_notification=True)
            return False

        target_user = get_most_recent_pending_user(admin_user_id)
        if not target_user:
            telegram_send_message("No pending users right now.", disable_notification=True)
            return False

        if not admin_user:
            telegram_send_message("No sender account found on the blog.", disable_notification=True)
            return False

        reply_message = Message(sender_id=admin_user.id, receiver_id=target_user.id)
        reply_message.set_encrypted_content(reply_text)
        db.session.add(reply_message)
        db.session.commit()
        publish_mobile_event('new_message', serialize_chat_message(reply_message))
        telegram_send_message(
            f"Reply sent to {target_user.username} (user_id={target_user.id}).",
            disable_notification=True
        )
        return True

    if command_token in ('/start', '/help'):
        telegram_send_message(
            "🤖 MyBlog Telegram admin is active.\n"
            "Use the emoji keyboard for user-friendly control:\n"
            "📝 Posts, 👥 Users, 💬 Comments, 📨 Messages.\n"
            "Quick commands:\n"
            "/menu, /status, /posts [page], /users [page], /comments [page]\n"
            "/finduser <query>, /findpost <query>, /list, /pending\n"
            "/reply <user_id_or_username> <message>\n"
            "/replylast <message>\n"
            "/cancel",
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if command_token == '/reply' and len(command_parts) == 1:
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        lines = [
            "💬 Reply helper:",
            "1) Send: /reply <user_id_or_username>",
            "2) Then send your text message.",
            "",
            "⏳ Pending users:"
        ]
        lines.extend(_format_blog_users_lines("Pending", users_pending_reply))
        telegram_send_message("\n".join(lines), reply_markup=telegram_main_menu_markup())
        return False

    target_user_ref, reply_text = parse_telegram_reply_command(incoming_text)
    if command_token == '/reply' and target_user_ref:
        target_user = resolve_blog_user_reference(target_user_ref)
        if not target_user:
            telegram_send_message(
                "❌ Unknown target user.\nUse /users to see valid usernames/user_ids.",
                disable_notification=True,
                reply_markup=telegram_main_menu_markup()
            )
            return False

        # Two-step reply mode: /reply <user>, then send plain text
        if not reply_text:
            telegram_reply_state[incoming_chat_id] = target_user.id
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(
                f"💬 Reply mode enabled for @{target_user.username} (id={target_user.id}).\n"
                "✍️ Now send your message text directly.\n"
                "❌ Use /cancel to stop."
            )
            return False

        admin_user = _first_admin_user()
        if not admin_user:
            telegram_send_message("No admin account found on the blog.", disable_notification=True)
            return False

        reply_message = Message(sender_id=admin_user.id, receiver_id=target_user.id)
        reply_message.set_encrypted_content(reply_text)
        db.session.add(reply_message)
        db.session.commit()
        publish_mobile_event('new_message', serialize_chat_message(reply_message))
        telegram_send_message(f"Reply sent to {target_user.username} (id={target_user.id}).", disable_notification=True)
        return True

    # If no command and reply mode exists, send to selected user
    if not command_token.startswith('/'):
        pending_target_user_id = telegram_reply_state.get(incoming_chat_id)
        if pending_target_user_id:
            admin_user = _bridge_admin_user()
            target_user = User.query.filter_by(id=pending_target_user_id, is_admin=False).first()
            if not admin_user or not target_user:
                telegram_send_message("Reply mode target not found. Use /reply again.", disable_notification=True)
                telegram_reply_state.pop(incoming_chat_id, None)
                return False

            reply_message = Message(sender_id=admin_user.id, receiver_id=target_user.id)

            # Support Telegram -> blog image/file replies.
            uploaded_file_path = None
            uploaded_file_type = None

            if incoming_photos:
                best_photo = incoming_photos[-1]
                photo_file_id = best_photo.get('file_id')
                uploaded_file_path = telegram_download_file_to_uploads(photo_file_id, preferred_ext='jpg')
                uploaded_file_type = 'image' if uploaded_file_path else None
            elif incoming_document:
                doc_file_id = incoming_document.get('file_id')
                mime_type = (incoming_document.get('mime_type') or '').lower()
                doc_name = incoming_document.get('file_name') or ''
                preferred_ext = os.path.splitext(doc_name)[1].lower().strip('.') if doc_name else 'bin'
                uploaded_file_path = telegram_download_file_to_uploads(doc_file_id, preferred_ext=preferred_ext or 'bin')
                if uploaded_file_path:
                    uploaded_file_type = 'image' if mime_type.startswith('image/') else 'file'

            outgoing_text = incoming_text or incoming_caption or ""
            reply_message.set_encrypted_content(outgoing_text)
            if uploaded_file_path:
                reply_message.file_path = uploaded_file_path
                reply_message.file_type = uploaded_file_type or 'file'

            db.session.add(reply_message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(reply_message))
            telegram_send_message(
                f"✅ Reply sent to @{target_user.username} (id={target_user.id}).\n"
                "Reply mode disabled.",
                reply_markup=telegram_main_menu_markup()
            )
            telegram_reply_state.pop(incoming_chat_id, None)
            return True

    if command_token == '/cancel':
        telegram_reply_state.pop(incoming_chat_id, None)
        _telegram_clear_admin_state(incoming_chat_id)
        telegram_send_message("❌ Reply mode cancelled.", disable_notification=True, reply_markup=telegram_main_menu_markup())
        return False

    if not target_user_ref or not reply_text:
        telegram_send_message(
            "❌ Invalid format.\nUse: /reply <user_id_or_username> <message>\n"
            "or /reply <user_id_or_username> then write your message.",
            disable_notification=True
        )
        return False

    admin_user = _bridge_admin_user()
    target_user = resolve_blog_user_reference(target_user_ref)
    if not admin_user or not target_user:
        telegram_send_message("❌ Unknown target user. Reply not sent.", disable_notification=True)
        return False

    reply_message = Message(sender_id=admin_user.id, receiver_id=target_user.id)
    reply_message.set_encrypted_content(reply_text)
    db.session.add(reply_message)
    db.session.commit()

    publish_mobile_event('new_message', serialize_chat_message(reply_message))
    telegram_send_message(f"✅ Reply sent to @{target_user.username} (id={target_user.id}).", disable_notification=True)
    return True


def telegram_fetch_updates(timeout=0):
    """Fetch bot updates and inject Telegram replies into website chat."""
    global telegram_last_update_id

    token = (os.environ.get('TELEGRAM_BOT_TOKEN') or '').strip()
    if not token:
        return 0

    timeout = max(0, min(int(timeout), 50))
    params = {'timeout': timeout}

    with telegram_update_lock:
        if telegram_last_update_id:
            params['offset'] = telegram_last_update_id

        url = f"https://api.telegram.org/bot{token}/getUpdates"
        try:
            response = requests.get(url, params=params, timeout=timeout + 10)
            data = response.json()
        except Exception:
            return 0

        if not data.get('ok'):
            return 0

        processed = 0
        for update in data.get('result', []):
            update_id = update.get('update_id')
            if isinstance(update_id, int):
                telegram_last_update_id = max(telegram_last_update_id, update_id + 1)

            callback_query = update.get('callback_query')
            if callback_query:
                process_telegram_callback_query(callback_query)

            message_data = update.get('message')
            if message_data and process_telegram_update_message(message_data):
                processed += 1

        return processed


def poll_telegram_updates_if_needed():
    global telegram_last_poll_at
    if not telegram_is_enabled():
        return

    now = time.time()
    if now - telegram_last_poll_at < 2:
        return

    telegram_last_poll_at = now
    telegram_fetch_updates(timeout=0)


def telegram_polling_worker():
    while True:
        try:
            with app.app_context():
                poll_telegram_updates_if_needed()
        except Exception:
            app.logger.exception("Telegram polling worker error")
        time.sleep(2)


def ensure_telegram_poller_started():
    global telegram_poller_started
    if not telegram_is_enabled():
        return

    with telegram_poller_lock:
        if telegram_poller_started:
            return
        Thread(target=telegram_polling_worker, daemon=True).start()
        telegram_poller_started = True


@app.before_request
def telegram_before_request_poll():
    # Keep Telegram bot commands responsive without JavaScript/webhooks.
    ensure_telegram_poller_started()
    poll_telegram_updates_if_needed()
    from app.utils import publish_scheduled_posts
    publish_scheduled_posts()


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.ckeditor.com; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    )
    return response


# Start Telegram polling as soon as routes are imported (even without web traffic).
ensure_telegram_poller_started()


def _conversation_latest_message_id(admin_id, user_id):
    latest = Message.query.filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id))
    ).order_by(Message.id.desc()).first()
    return latest.id if latest else 0


def wait_for_conversation_message(admin_id, user_id, last_seen_id, timeout_seconds=25):
    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        latest_id = _conversation_latest_message_id(admin_id, user_id)
        if latest_id > last_seen_id:
            return True

        remaining = int(deadline - time.time())
        if telegram_is_enabled() and remaining > 0:
            telegram_fetch_updates(timeout=min(8, remaining))
            latest_id = _conversation_latest_message_id(admin_id, user_id)
            if latest_id > last_seen_id:
                return True

        time.sleep(1)

    return False

# 🔹 Home Page
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


# 🔹 About Page
@app.route('/about')
def about():
    return render_template('about.html')


# 🔹 Editor Help Page
@app.route('/editor_help')
def editor_help():
    return render_template('editor_help.html')


# 🔹 Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        if _action_rate_limited('contact_submit', max_calls=8, window_seconds=300):
            flash('Too many contact attempts. Please wait a bit.', 'danger')
            return redirect(url_for('contact'))
        contact_msg = ContactMessage(
            name=form.name.data.strip(),
            email=form.email.data.strip(),
            message=form.message.data.strip()
        )
        db.session.add(contact_msg)
        db.session.commit()
        telegram_send_message(
            f"📬 New contact message from {contact_msg.name} ({contact_msg.email}):\n\n{contact_msg.message}"
        )
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)


# 🔹 View a Blog Post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    # Increment view counter once per session
    if request.method == 'GET':
        viewed_posts = session.get('viewed_posts', [])
        if post_id not in viewed_posts:
            post.views_count = (post.views_count or 0) + 1
            db.session.commit()
            viewed_posts.append(post_id)
            session['viewed_posts'] = viewed_posts

    if form.validate_on_submit():
        if current_user.is_authenticated:
            if _action_rate_limited('comment_submit', max_calls=12, window_seconds=300):
                flash('Too many comments in a short time. Please slow down.', 'danger')
                return redirect(url_for('post_detail', post_id=post.id))
            content = form.content.data.strip()
            if content:
                comment = Comment(content=parse_bbcode(content), post_id=post.id, author_id=current_user.id)
                db.session.add(comment)
                db.session.commit()
                
                # Add experience points for commenting
                current_user.add_experience(3)
                
                # Create notification for post author
                if post.author_id != current_user.id:
                    notification = Notification(
                        user_id=post.author_id,
                        type='comment',
                        title='New comment!',
                        message=f'Someone commented on your article "{post.title}"',
                        related_post_id=post.id,
                        related_comment_id=comment.id
                    )
                    db.session.add(notification)
                    
                    # Emit real-time notification
                    socketio.emit('notification', {
                        'type': 'comment',
                        'title': 'New comment!',
                        'message': f'{current_user.username} commented on your article "{post.title}"',
                        'user_id': post.author_id
                    })
                
                # Check and award badges
                check_and_award_badges(current_user)
                
                db.session.commit()
                flash('Your comment has been posted!', 'success')
            else:
                flash('Comment cannot be empty.', 'danger')
        else:
            flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('post_detail', post_id=post.id))

    # BBCode render (server-side)
    post.content = parse_bbcode(post.content)

    return render_template('post_detail.html', post=post, form=form)


# 🔹 Register a User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)


# 🔹 Login a User
@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', max_calls=5, window_seconds=300)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.totp_enabled:
                # Store pre-auth state in session; do NOT log in yet
                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_remember'] = form.remember_me.data
                return redirect(url_for('login_totp'))
            login_user(user, remember=form.remember_me.data)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)


# 🔹 TOTP second-step verification
@app.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """Second step: verify 6-digit TOTP code after successful password check."""
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        # No pending pre-auth — redirect to login
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.totp_enabled:
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_remember', None)
        return redirect(url_for('login'))

    form = TOTPVerifyForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.code.data.strip(), valid_window=1):
            remember = session.pop('pre_2fa_remember', False)
            session.pop('pre_2fa_user_id', None)
            login_user(user, remember=remember)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('login_totp.html', form=form)


# 🔹 Logout a User
@app.route('/logout')
def logout():
    # Clear any pending pre-2FA session state
    session.pop('pre_2fa_user_id', None)
    session.pop('pre_2fa_remember', None)
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# 🔹 Admin Dashboard
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    # Get statistics for dashboard
    total_posts = Post.query.count()
    total_users = User.query.count()
    total_comments = Comment.query.count()
    total_banners = Banner.query.count()
    
    return render_template('admin_dashboard.html', 
                         total_posts=total_posts,
                         total_users=total_users,
                         total_comments=total_comments,
                         total_banners=total_banners)


# 🔹 Donate Page
@app.route('/donate', methods=['GET', 'POST'])
def donate():
    form = EmptyForm()

    if request.method == 'POST':
        amount = float(request.form.get('amount', 0))
        if amount > 0:
            new_donor = Donor(name='Anonymous', amount=amount)
            db.session.add(new_donor)
            db.session.commit()
            flash("Thank you for your donation!", "success")
        return redirect(url_for('donate'))

    top_donors = Donor.query.order_by(Donor.amount.desc()).limit(5).all()
    return render_template('donate.html', form=form, top_donors=top_donors)


# File Upload Configuration
UPLOAD_FOLDER = 'uploads'
MAX_UPLOAD_BYTES = int((os.environ.get('MAX_UPLOAD_BYTES') or str(10 * 1024 * 1024)).strip())
CHAT_ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp',
    'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', '7z',
    'mp3', 'mp4', 'avi', 'mov', 'mkv', 'csv', 'xls', 'xlsx',
    'ppt', 'pptx', 'json', 'xml', 'svg', 'webm', 'ogg'
}
PROFILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'}
ALLOWED_MIME_EXACT = {
    'application/pdf', 'application/zip', 'application/json', 'application/xml',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/x-7z-compressed', 'application/x-rar-compressed',
    'text/plain', 'text/csv'
}
ALLOWED_MIME_PREFIXES = ('image/', 'video/', 'audio/', 'text/')


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

# Function to modify image metadata
def modify_exif_data(file_path):
    try:
        image = Image.open(file_path)
        exif_dict = piexif.load(image.info.get('exif', b''))

        # Remove GPS information
        if 'GPS' in exif_dict:
            exif_dict['GPS'] = {}

        # Add custom tag
        exif_dict['0th'][piexif.ImageIFD.Make] = "Modified"
        exif_dict['0th'][piexif.ImageIFD.Model] = "Edited"
        exif_dict['0th'][piexif.ImageIFD.Software] = "ChatUploader"

        exif_bytes = piexif.dump(exif_dict)
        image.save(file_path, "jpeg", exif=exif_bytes)
    except Exception as e:
        print(f"EXIF modification error: {e}")

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = EmptyForm()

    if request.method == 'POST':
        if _action_rate_limited('chat_submit', max_calls=30, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('chat'))
        message_content = request.form.get('message', '').strip()
        file = request.files.get('file')

        # Handle file uploads
        if file and file.filename:
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                max_bytes=MAX_UPLOAD_BYTES
            )
            if is_valid:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"chat_{current_user.id}_admin_{timestamp}_{filename}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                # Modify image metadata if it's an image
                if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                    modify_exif_data(file_path)

                # Determine file type
                file_type = get_file_type(file.filename)

                # Save message with file using proper fields
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=_get_admin_user_id(),  # actual admin
                    content=message_content if message_content else "",
                    file_path=file_path,
                    file_type=file_type
                )
                db.session.add(message)
                db.session.commit()
                publish_mobile_event('new_message', serialize_chat_message(message))
                notify_admin_telegram_new_message(message)
                flash("File sent!", "success")
            else:
                flash(f"File upload failed: {validation_msg}", "danger")

        elif message_content:
            # Save text message
            message = Message(
                sender_id=current_user.id,
                receiver_id=_get_admin_user_id(),  # actual admin
                content=message_content
            )
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            notify_admin_telegram_new_message(message)
            flash("Message sent!", "success")

        return redirect(url_for('chat'))

    # Get messages from most recent to oldest
    messages = Message.query.order_by(Message.timestamp.desc()).all()

    return render_template('chat.html', form=form, messages=messages)

@socketio.on('message')
def handle_message(data):
    msg = data.get('msg', '').strip()
    sender_id = current_user.id if current_user.is_authenticated else None
    receiver_id = _get_admin_user_id()  # actual admin

    if msg and sender_id:
        message = Message(sender_id=sender_id, receiver_id=receiver_id, content=msg)
        db.session.add(message)
        db.session.commit()
        publish_mobile_event('new_message', serialize_chat_message(message))
        notify_admin_telegram_new_message(message)

        # Émet le message à tous les clients connectés
        emit('message', {"username": current_user.username, "msg": msg}, broadcast=True)


@app.route('/admin/chat')
@admin_required
def admin_chat():
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get all messages
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    
    return render_template('admin_chat.html', messages=messages, users=users)


@app.route('/admin/chat/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_chat_user(user_id):
    # Get target user
    target_user = User.query.get_or_404(user_id)

    # Wait-mode endpoint: block shortly and refresh only when new message is available
    wait_mode = request.args.get('wait') == '1'
    last_seen_id = request.args.get('last_seen_id', type=int, default=0)
    if request.method == 'GET' and wait_mode:
        has_new_message = wait_for_conversation_message(current_user.id, user_id, last_seen_id, timeout_seconds=25)
        if has_new_message:
            return redirect(url_for('admin_chat_user', user_id=user_id))
        return redirect(url_for('admin_chat_user', user_id=user_id, wait=1, last_seen_id=last_seen_id))
    
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get messages between admin and this user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Handle message sending
    if request.method == 'POST':
        if _action_rate_limited('admin_chat_submit', max_calls=60, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('admin_chat_user', user_id=user_id))
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
        
        if content or file:
            message = Message(
                sender_id=current_user.id,
                receiver_id=user_id
            )
            
            # Handle text content
            if content:
                message.set_encrypted_content(content)
            else:
                message.set_encrypted_content("")
            
            # Handle file upload
            if file and file.filename:
                is_valid, validation_msg = _validate_uploaded_file(
                    file,
                    allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                    max_bytes=MAX_UPLOAD_BYTES
                )
                if is_valid:
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"chat_{current_user.id}_{user_id}_{timestamp}_{filename}"
                    file_path = os.path.join('uploads', filename)
                    file.save(file_path)
                    # Media pipeline
                    processed = process_image_file(file_path)
                    if processed != file_path:
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
                        file_path = processed
                    message.file_path = file_path
                    message.file_type = get_file_type(file.filename)
                else:
                    flash(f'File upload blocked: {validation_msg}', 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
            
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            
            # Emit message via SocketIO
            socketio.emit('message', {
                'username': current_user.username,
                'msg': content if content else f"File sent: {file.filename}",
                'receiver_id': user_id,
                'file_path': message.file_path,
                'file_type': message.file_type
            })
            
            flash('Message sent!', 'success')
            return redirect(url_for('admin_chat_user', user_id=user_id))

    # Pull Telegram replies (if configured) before rendering chat page
    telegram_fetch_updates(timeout=0)
    # Reload list after potential Telegram sync
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    latest_message_id = messages[-1].id if messages else 0

    return render_template('admin_chat_user.html', 
                         messages=messages, 
                         users=users, 
                         target_user=target_user,
                         latest_message_id=latest_message_id,
                         telegram_bridge_enabled=telegram_is_enabled())


@app.route('/api/admin/mobile/ping', methods=['GET'])
@admin_api_required
def api_admin_mobile_ping():
    admin_user = request.admin_api_user
    return jsonify({
        'status': 'ok',
        'admin': {
            'id': admin_user.id,
            'username': admin_user.username
        }
    })


@app.route('/api/admin/mobile/conversations', methods=['GET'])
@admin_api_required
def api_admin_mobile_conversations():
    admin_user = request.admin_api_user
    users = User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()

    conversations = []
    for user in users:
        last_message = Message.query.filter(
            ((Message.sender_id == admin_user.id) & (Message.receiver_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.receiver_id == admin_user.id))
        ).order_by(Message.timestamp.desc()).first()

        conversations.append({
            'user': {
                'id': user.id,
                'username': user.username,
                'level': user.level,
                'experience_points': user.experience_points
            },
            'last_message': serialize_chat_message(last_message) if last_message else None
        })

    return jsonify({'conversations': conversations})


@app.route('/api/admin/mobile/conversations/<int:user_id>/messages', methods=['GET'])
@admin_api_required
def api_admin_mobile_messages(user_id):
    admin_user = request.admin_api_user
    limit = request.args.get('limit', default=50, type=int)
    limit = max(1, min(limit, 200))

    target_user = User.query.filter_by(id=user_id, is_admin=False).first_or_404()
    messages = Message.query.filter(
        ((Message.sender_id == admin_user.id) & (Message.receiver_id == target_user.id)) |
        ((Message.sender_id == target_user.id) & (Message.receiver_id == admin_user.id))
    ).order_by(Message.timestamp.desc()).limit(limit).all()

    messages = list(reversed(messages))
    return jsonify({
        'conversation': {
            'admin_id': admin_user.id,
            'user_id': target_user.id,
            'user_username': target_user.username
        },
        'messages': [serialize_chat_message(message) for message in messages]
    })


@app.route('/api/admin/mobile/conversations/<int:user_id>/messages', methods=['POST'])
@csrf.exempt
@admin_api_required
def api_admin_mobile_send_message(user_id):
    admin_user = request.admin_api_user
    target_user = User.query.filter_by(id=user_id, is_admin=False).first_or_404()

    payload = request.get_json(silent=True) or {}
    content = (payload.get('content') or '').strip()

    if not content:
        return jsonify({'error': 'Message content is required.'}), 400

    message = Message(
        sender_id=admin_user.id,
        receiver_id=target_user.id
    )
    message.set_encrypted_content(content)
    db.session.add(message)
    db.session.commit()

    serialized_message = serialize_chat_message(message)
    publish_mobile_event('new_message', serialized_message)

    return jsonify({'message': serialized_message}), 201


@app.route('/api/admin/mobile/stream', methods=['GET'])
@admin_api_required
def api_admin_mobile_stream():
    admin_user = request.admin_api_user
    subscriber_queue = queue.Queue(maxsize=100)

    with mobile_event_lock:
        mobile_event_subscribers.append(subscriber_queue)

    def event_stream():
        try:
            welcome = {
                'type': 'connected',
                'payload': {
                    'admin_id': admin_user.id,
                    'username': admin_user.username
                },
                'created_at': datetime.utcnow().isoformat() + 'Z'
            }
            yield f"data: {json.dumps(welcome)}\n\n"

            while True:
                try:
                    event = subscriber_queue.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    heartbeat = {'type': 'heartbeat', 'created_at': datetime.utcnow().isoformat() + 'Z'}
                    yield f"data: {json.dumps(heartbeat)}\n\n"
        finally:
            with mobile_event_lock:
                if subscriber_queue in mobile_event_subscribers:
                    mobile_event_subscribers.remove(subscriber_queue)

    response = Response(stream_with_context(event_stream()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Route to serve uploaded files"""
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    return send_from_directory(upload_dir, filename)

@app.route('/static/uploads/<filename>')
def static_uploaded_file(filename):
    """Route to serve uploaded files from static/uploads"""
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    return send_from_directory(upload_dir, filename)


# 🔹 File Upload Route



@app.route('/manage_posts', methods=['GET', 'POST'])
@admin_required
def manage_posts():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        scheduled_date = form.scheduled_date.data or datetime.utcnow()
        is_published = form.is_published.data
        post = Post(
            title=title,
            content=content,
            author_id=current_user.id,
            scheduled_date=scheduled_date,
            is_published=is_published
        )
        db.session.add(post)
        db.session.commit()
        
        # Add experience points for creating a post
        current_user.add_experience(10)
        
        # Vérifier et attribuer les badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('manage_posts'))
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('manage_posts.html', form=form, posts=posts)

@app.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    users = User.query.all()
    form = EmptyForm()
    return render_template('manage_users.html', users=users, form=form)


@app.route('/manage_comments', methods=['GET', 'POST'])
@admin_required
def manage_comments():
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    form = EmptyForm()
    return render_template('manage_comments.html', comments=comments, form=form)

@app.route('/site_statistics')
@admin_required
def site_statistics():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    # Trouver l'utilisateur avec le plus de posts
    most_active_user = db.session.query(User.username, db.func.count(Post.id).label('post_count'))\
        .join(Post).group_by(User.id).order_by(db.func.count(Post.id).desc()).first()

    return render_template('site_statistics.html',
                           total_users=total_users,
                           total_admins=total_admins,
                           total_posts=total_posts,
                           total_comments=total_comments,
                           most_active_user=most_active_user)

@app.route('/manage_banners', methods=['GET', 'POST'])
@admin_required
def manage_banners():
    form = BannerForm()
    banners = Banner.query.all()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        image_url = form.image_url.data
        link_url = form.link_url.data
        position = form.position.data
        is_active = form.is_active.data
        
        banner = Banner(
            title=title,
            content=content,
            image_url=image_url,
            link_url=link_url,
            position=position,
            is_active=is_active
        )
        
        db.session.add(banner)
        db.session.commit()
        flash('Banner created successfully!', 'success')
        return redirect(url_for('manage_banners'))

    return render_template('manage_banners.html', banners=banners, form=form)



UPLOAD_FILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def get_file_type(filename):
    """Détermine le type de fichier basé sur l'extension"""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv']:
        return 'video'
    else:
        return 'file'

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if _action_rate_limited('upload_file_submit', max_calls=12, window_seconds=300):
        flash('Too many uploads. Please wait a bit.', 'danger')
        return redirect(url_for('chat'))
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('chat'))

    file = request.files['file']

    if file.filename == '':
        flash('No file uploaded!', 'danger')
        return redirect(url_for('chat'))

    is_valid, validation_msg = _validate_uploaded_file(
        file,
        allowed_exts=UPLOAD_FILE_ALLOWED_EXTENSIONS,
        max_bytes=MAX_UPLOAD_BYTES,
        image_only=True
    )
    if not is_valid:
        flash(f'Invalid file type! {validation_msg}', 'danger')
        return redirect(url_for('chat'))

    # Secure filename
    filename = secure_filename(file.filename)
    file_path = os.path.join('uploads', filename)

    # Save file
    file.save(file_path)

    # Verify if it's a valid image by trying to open it with PIL
    try:
        with Image.open(file_path) as img:
            img.verify()  # Quick integrity check
    except Exception:
        os.remove(file_path)  # Remove file if it's not a valid image
        flash('Invalid image file!', 'danger')
        return redirect(url_for('chat'))

    # Modify image metadata
    modify_exif_data(file_path)

    flash('Image uploaded and metadata modified successfully!', 'success')
    return redirect(url_for('chat'))

@app.route('/manage_pages', methods=['GET', 'POST'])
@admin_required
def manage_pages():
    pages = StaticPage.query.all()
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, slug=form.slug.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('manage_pages'))

    return render_template('manage_pages.html', pages=pages, form=form)




@app.route('/demote_user/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        user.is_admin = False
        db.session.commit()
        flash(f'User {user.username} has been demoted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_page', methods=['GET', 'POST'])
@admin_required
def create_page():
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash('New page created!', 'success')
        return redirect(url_for('manage_pages'))

    return render_template('create_page.html', form=form)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_posts'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/promote_user/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f"{user.username} has been promoted to admin.", "success")
    return redirect(url_for('manage_users'))






@app.route("/delete_comment/<int:comment_id>/<int:post_id>", methods=["POST"]) 
@rate_limit('delete_comment', max_calls=15, window_seconds=300)
@login_required
def delete_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)

    # Admin can delete everything, otherwise user can only delete their own comments
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully!", "success")
    return redirect(url_for("post_detail", post_id=post_id))



@app.route("/posts")
def post_list():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template("post_list.html", posts=posts)

@app.route("/reply_to_comment/<int:post_id>/<int:comment_id>", methods=["POST"])
@rate_limit('reply_to_comment', max_calls=10, window_seconds=300)
@login_required
def reply_to_comment(post_id, comment_id):
    post = Post.query.get_or_404(post_id)
    parent_comment = Comment.query.get_or_404(comment_id)

    form = CommentForm()

    if form.validate_on_submit():
        reply = Comment(
            content=form.content.data,
            author=current_user,
            post_id=post.id,
            parent_id=parent_comment.id
        )
        db.session.add(reply)
        db.session.commit()
        
        # Add experience points for reply
        current_user.add_experience(2)
        
        # Create notification for parent comment author
        if parent_comment.author_id and parent_comment.author_id != current_user.id:
            notification = Notification(
                user_id=parent_comment.author_id,
                type='reply',
                title='New reply!',
                message=f'Someone replied to your comment',
                related_post_id=post.id,
                related_comment_id=reply.id
            )
            db.session.add(notification)
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'reply',
                'title': 'New reply!',
                'message': f'Someone replied to your comment',
                'user_id': parent_comment.author_id
            })
        
        # Vérifier et attribuer les badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash("Your reply has been added!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
    return redirect(url_for("post_detail", post_id=post.id))


@app.route("/edit_comment/<int:comment_id>/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)
    post = Post.query.get_or_404(post_id)

    # L'admin peut modifier tous les commentaires, sinon l'utilisateur ne peut modifier que les siens
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    form = CommentForm()
    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash("Comment updated!", "success")
        return redirect(url_for("post_detail", post_id=post_id))

    form.content.data = comment.content
    return render_template("edit_comment.html", title="Edit Comment", form=form, post=post, comment=comment)  # 🔥 Passe `post`


# 🔹 Système de Likes/Upvotes
@app.route('/like_post/<int:post_id>', methods=['POST'])
@rate_limit('like_post', max_calls=20, window_seconds=300)
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        post.likes_count = max(0, post.likes_count - 1)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        post.likes_count += 1
        
        # Add experience points to post author
        if post.author_id != current_user.id:
            post.author.add_experience(5)
            
            # Create notification for author
            notification = Notification(
                user_id=post.author_id,
                type='like',
                title='New like!',
                message=f'Someone liked your article "{post.title}"',
                related_post_id=post_id
            )
            db.session.add(notification)
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'like',
                'title': 'New like!',
                'message': f'{current_user.username} liked your article "{post.title}"',
                'user_id': post.author_id
            })
        
        flash('Article liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Check if user already liked this comment
    existing_like = Like.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        comment.likes_count = max(0, comment.likes_count - 1)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        comment.likes_count += 1
        
        # Add experience points to comment author
        if comment.author_id and comment.author_id != current_user.id:
            comment.author.add_experience(2)
            
            # Créer une notification pour l'auteur
            notification = Notification(
                user_id=comment.author_id,
                type='like',
                title='Comment liked!',
                message=f'{current_user.username} liked your comment',
                related_comment_id=comment_id,
                related_post_id=comment.post_id
            )
            db.session.add(notification)
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'like',
                'title': 'Comment liked!',
                'message': f'{current_user.username} liked your comment',
                'user_id': comment.author_id
            })
        
        flash('Comment liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=comment.post_id))


# 🔹 Système de Notifications
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).all()
    form = EmptyForm()
    return render_template('notifications.html', notifications=user_notifications, form=form)


@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False)\
        .update({'is_read': True})
    db.session.commit()
    flash('All notifications were marked as read!', 'success')
    return redirect(url_for('notifications'))


# 🔹 Système de Badges et Niveaux
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_posts = Post.query.filter_by(author_id=user_id, is_published=True).order_by(Post.date_posted.desc()).limit(5).all()
    user_comments = Comment.query.filter_by(author_id=user_id).order_by(Comment.date_posted.desc()).limit(5).all()
    
    # Calculer les statistiques
    total_posts = Post.query.filter_by(author_id=user_id, is_published=True).count()
    total_comments = Comment.query.filter_by(author_id=user_id).count()
    total_likes_received = db.session.query(db.func.sum(Post.likes_count))\
        .filter(Post.author_id == user_id).scalar() or 0
    
    return render_template('user_profile.html', 
                         user=user, 
                         user_posts=user_posts,
                         user_comments=user_comments,
                         total_posts=total_posts,
                         total_comments=total_comments,
                         total_likes_received=total_likes_received)


# Function to create default badges
def create_default_badges():
    """Creates default system badges"""
    default_badges = [
        {
            'name': 'Premier Post',
            'description': 'A publié son premier article',
            'icon': 'fas fa-feather-alt',
            'color': '#8b93ff',
            'condition': 'first_post',
            'points_reward': 50
        },
        {
            'name': 'Commentateur Actif',
            'description': 'A publié 10 commentaires',
            'icon': 'fas fa-comments',
            'color': '#51cf66',
            'condition': '10_comments',
            'points_reward': 30
        },
        {
            'name': 'Auteur Prolifique',
            'description': 'A publié 5 articles',
            'icon': 'fas fa-pen-fancy',
            'color': '#ffd43b',
            'condition': '5_posts',
            'points_reward': 100
        },
        {
            'name': 'Populaire',
            'description': 'Un de ses articles a reçu 10 likes',
            'icon': 'fas fa-fire',
            'color': '#ff6b6b',
            'condition': '10_likes_post',
            'points_reward': 75
        },
        {
            'name': 'Niveau 5',
            'description': 'A atteint le niveau 5',
            'icon': 'fas fa-star',
            'color': '#9c88ff',
            'condition': 'level_5',
            'points_reward': 0
        }
    ]
    
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
                
                # Émettre une notification temps réel
                socketio.emit('notification', {
                    'type': 'badge',
                    'title': 'New badge unlocked!',
                    'message': f'You unlocked the badge "{badge.name}": {badge.description}',
                    'user_id': user.id
                })
                
                flash(f'Congrats! You unlocked the badge "{badge.name}"!', 'success')


# 🔹 Route pour initialiser les badges (à appeler une seule fois)
@app.route('/init_badges')
@admin_required
def init_badges():
    create_default_badges()
    flash('Default badges created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# 🔹 Édition du profil utilisateur
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(original_username=current_user.username)
    
    if form.validate_on_submit():
        # Mettre à jour le nom d'utilisateur
        current_user.username = form.username.data
        
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=PROFILE_ALLOWED_EXTENSIONS,
                max_bytes=min(MAX_UPLOAD_BYTES, 3 * 1024 * 1024),
                image_only=True
            )
            if is_valid:
                filename = secure_filename(file.filename)
                # Create unique name to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"profile_{current_user.id}_{timestamp}_{filename}"
                file_path = os.path.join('uploads', filename)
                file.save(file_path)
                
                # Remove old photo if it exists
                if current_user.profile_picture and os.path.exists(current_user.profile_picture):
                    os.remove(current_user.profile_picture)
                
                current_user.profile_picture = file_path
            else:
                flash(f'Profile picture rejected: {validation_msg}', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    # Pre-fill form with current data
    form.username.data = current_user.username
    
    return render_template('edit_profile.html', form=form)


# ─────────────────────────────────────────────────────────────────
#  TOTP / 2FA routes
# ─────────────────────────────────────────────────────────────────

def _totp_qr_data_uri(secret: str, username: str) -> str:
    """Return a data: URI PNG of the provisioning QR code (no file on disk)."""
    import qrcode
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MyBlog'
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode('ascii')
    return f'data:image/png;base64,{b64}'


@app.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    """Generate a new TOTP secret and show the QR code.
    On POST with a valid 6-digit code, activate 2FA for the user.
    """
    if current_user.totp_enabled:
        flash('Two-factor authentication is already active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPSetupForm()

    # Generate (or reuse pending) secret stored in session
    if 'totp_pending_secret' not in session:
        session['totp_pending_secret'] = pyotp.random_base32()

    pending_secret = session['totp_pending_secret']

    if form.validate_on_submit():
        totp = pyotp.TOTP(pending_secret)
        if totp.verify(form.code.data.strip(), valid_window=1):
            current_user.totp_secret = pending_secret
            current_user.totp_enabled = True
            db.session.commit()
            session.pop('totp_pending_secret', None)
            flash('Two-factor authentication has been enabled!', 'success')
            return redirect(url_for('user_profile', user_id=current_user.id))
        else:
            flash('Invalid code. Please try again.', 'danger')

    qr_uri = _totp_qr_data_uri(pending_secret, current_user.username)
    return render_template(
        'totp_setup.html',
        form=form,
        qr_uri=qr_uri,
        totp_secret=pending_secret
    )


@app.route('/totp/disable', methods=['GET', 'POST'])
@login_required
def totp_disable():
    """Disable 2FA after confirming current password + a valid TOTP code."""
    if not current_user.totp_enabled:
        flash('Two-factor authentication is not currently active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPDisableForm()

    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password, form.password.data):
            flash('Incorrect password.', 'danger')
            return render_template('totp_disable.html', form=form)

        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(form.code.data.strip(), valid_window=1):
            flash('Invalid authentication code.', 'danger')
            return render_template('totp_disable.html', form=form)

        current_user.totp_enabled = False
        current_user.totp_secret = None
        db.session.commit()
        flash('Two-factor authentication has been disabled.', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))

    return render_template('totp_disable.html', form=form)
