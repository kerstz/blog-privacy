"""Telegram admin bot: manage posts/users/comments and reply to chats from
Telegram (optional, enabled by TELEGRAM_BOT_TOKEN + TELEGRAM_ADMIN_CHAT_ID)."""
from app import app, db
from app.models import User, Post, Comment, Message
from app.utils import hit_rate_limit
from datetime import datetime
import re
import os
import sqlite3
import json
import time
import uuid
import requests
from threading import Lock, Thread
import hmac
from app.services import (
    encrypt_upload_in_place,
    read_upload_bytes,
    upload_display_name,
    _absolute_upload_path,
    _bridge_admin_user,
    _conversation_latest_message_id,
    _delete_post_and_children,
    _delete_user_and_data,
    _first_admin_user,
    _to_positive_int,
    publish_mobile_event,
    serialize_chat_message,
)


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
        payload = read_upload_bytes(file_path)
        response = requests.post(url, data=data, files={'photo': (upload_display_name(file_path), payload)}, timeout=20)
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
        payload = read_upload_bytes(file_path)
        response = requests.post(url, data=data, files={'document': (upload_display_name(file_path), payload)}, timeout=20)
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
    if not ext or len(ext) > 8 or not ext.isalnum():
        ext = preferred_ext
    if not ext or len(ext) > 8 or not ext.isalnum():
        ext = 'bin'

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
        encrypted = encrypt_upload_in_place(absolute_path)
        return os.path.join('uploads', os.path.basename(encrypted))
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
        post = db.session.get(Post, post_id) if post_id else None
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
        post = db.session.get(Post, post_id) if post_id else None
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
        user = db.session.get(User, user_id) if user_id else None
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
        user = db.session.get(User, user_id) if user_id else None
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
        user = db.session.get(User, user_id) if user_id else None
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
        comment = db.session.get(Comment, comment_id) if comment_id else None
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

    command_name = ''
    command_parts = []
    if incoming_text and incoming_text.startswith('/'):
        command_name = incoming_text.split()[0].lower()
        if '@' in command_name:
            command_name = command_name.split('@', 1)[0]
        command_parts = incoming_text.strip().split(maxsplit=2)

    admin_state = _telegram_get_admin_state(incoming_chat_id)
    pin = (os.environ.get('TELEGRAM_ADMIN_PIN') or '').strip()

    if command_name == '/start':
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
        if command_name == '/cancel':
            _telegram_clear_admin_state(incoming_chat_id)
            _telegram_clear_session(incoming_actor_id)
            telegram_send_message("❌ Session auth cancelled.")
            return False
        if (
            admin_state
            and admin_state.get('mode') == 'await_pin'
            and str(admin_state.get('actor_user_id', '')) == incoming_actor_id
            and incoming_text
            and not command_name.startswith('/')
        ):
            if hit_rate_limit(f"tg_pin_fail:{incoming_actor_id}", 5, 900, record=False):
                telegram_send_message("⛔ Too many wrong PINs. Locked for 15 minutes.")
                return False
            if hmac.compare_digest(incoming_text.strip().encode(), pin.encode()):
                _telegram_clear_admin_state(incoming_chat_id)
                _telegram_start_session(incoming_actor_id)
                telegram_send_message("✅ PIN accepted. Control panel unlocked.", reply_markup=telegram_main_menu_markup())
            else:
                hit_rate_limit(f"tg_pin_fail:{incoming_actor_id}", 5, 900)
                _telegram_audit_log(incoming_actor_id, "wrong_pin")
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

    if incoming_text == "📊 Status" or command_name == '/status':
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

    if incoming_text == "📋 List posts" or command_name == '/posts':
        page = _to_positive_int(command_parts[1]) if len(command_parts) > 1 else 1
        offset = max(0, ((page or 1) - 1) * 6)
        telegram_send_posts_page(offset=offset, page_size=6)
        return False

    if incoming_text == "📋 List users":
        telegram_send_users_page(offset=0, page_size=8)
        return False

    if incoming_text == "📋 List comments" or command_name == '/comments':
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
        command_name = '/cancel'

    # ----- Stateful admin actions for post/user/comment management -----
    if admin_state and not command_name.startswith('/'):
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
                scheduled_date=None
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
            post = db.session.get(Post, post_id) if post_id else None
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
            post = db.session.get(Post, post_id) if post_id else None
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
            user = db.session.get(User, user_id) if user_id else None
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
            user = db.session.get(User, user_id) if user_id else None
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
            user = db.session.get(User, user_id) if user_id else None
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
            comment = db.session.get(Comment, comment_id) if comment_id else None
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
            post = db.session.get(Post, post_id) if post_id else None
            if not post:
                _telegram_clear_admin_state(incoming_chat_id)
                telegram_send_message("❌ Post not found anymore.", reply_markup=telegram_posts_menu_markup())
                return False
            post_title = post.title
            _delete_post_and_children(post)
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
            user = db.session.get(User, user_id) if user_id else None
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
            fallback_admin = User.query.filter(User.is_admin.is_(True), User.id != user.id).order_by(User.id.asc()).first()
            if not fallback_admin:
                telegram_send_message("🛡️ Blocked: no other admin to take over the posts.")
                return False
            _delete_user_and_data(user, new_post_owner_id=fallback_admin.id)
            _telegram_audit_log(incoming_actor_id, "delete_user", f"user_id={user_id} username={username}")
            _telegram_clear_admin_state(incoming_chat_id)
            telegram_send_message(f"🗑️ User @{username} deleted.", reply_markup=telegram_users_menu_markup())
            return False

        if mode == "confirm_delete_comment":
            if incoming_text != "✅ Confirm":
                telegram_send_message("⚠️ Press '✅ Confirm' or '❌ Cancel'.", reply_markup=telegram_confirm_menu_markup())
                return False
            comment_id = _to_positive_int(admin_state.get('comment_id'))
            comment = db.session.get(Comment, comment_id) if comment_id else None
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

    if command_name == '/list':
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

    if command_name == '/users':
        page = _to_positive_int(command_parts[1]) if len(command_parts) > 1 else 1
        offset = max(0, ((page or 1) - 1) * 8)
        telegram_send_users_page(offset=offset, page_size=8)
        return False

    if command_name == '/finduser':
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

    if command_name == '/findpost':
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

    if command_name == '/sent':
        users_with_messages = _blog_users_with_messages(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("📨 Users who sent messages", users_with_messages)),
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if command_name == '/pending':
        users_pending_reply = _blog_users_pending_reply(admin_user_id)
        telegram_send_message(
            "\n".join(_format_blog_users_lines("⏳ Pending (not replied/seen yet)", users_pending_reply)),
            reply_markup=telegram_main_menu_markup()
        )
        return False

    if command_name == '/replylast':
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

    if command_name in ('/start', '/help'):
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

    if command_name == '/reply' and len(command_parts) == 1:
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
    if command_name == '/reply' and target_user_ref:
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
    if not command_name.startswith('/'):
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

    if command_name == '/cancel':
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
            # bandit B113: timeout is set
            response = requests.get(url, params=params, timeout=timeout + 10)  # nosec B113
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
