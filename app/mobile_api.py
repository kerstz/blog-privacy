"""Mobile admin REST API (HTTP Basic Auth + TOTP header, SSE event stream)."""
from flask import request, jsonify, Response, stream_with_context, abort
from app import app, db, csrf, bcrypt
from app.models import User, Message
from app.utils import (anonymous_client_key, client_ip_is_meaningful, hashed_key, record_failure,
                       too_many_failures, clear_failures)
from functools import wraps
from datetime import datetime
import json
import base64
import os
import queue
from app.services import (
    _DUMMY_PASSWORD_HASH,
    _verify_totp_once,
    mobile_event_lock,
    mobile_event_subscribers,
    publish_mobile_event,
    serialize_chat_message,
)

# Lockout of the mobile API: per username (strict) and per client (wide).
# Behind an onion service every client shares the same address: the per-client
# limit is therefore global, hence a higher threshold than per username.
ADMIN_API_USER_MAX_FAILURES = 10
ADMIN_API_CLIENT_MAX_FAILURES = 30
ADMIN_API_LOCKOUT_SECONDS = 900


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


def _mobile_api_enabled():
    return os.environ.get('MOBILE_API_ENABLED', 'true').strip().lower() \
        not in ('0', 'false', 'no', 'off')


def _admin_api_error(message, status, **headers):
    return jsonify({'error': message}), status, headers


def authenticate_admin_api():
    """Authenticate the Basic Auth call. Returns (user, None) or (None, response).

    - a bcrypt check is always made, even for an unknown username (otherwise the
      timing reveals which usernames are admins);
    - lockout after repeated failures, per username and per client (429 +
      Retry-After);
    - banned accounts and accounts that must change their password are refused;
    - accounts with 2FA must send the current code in `X-TOTP-Code`.
    """
    username, password = parse_basic_auth()
    if not username or not password:
        return None, _admin_api_error(
            'Authentication required for admin mobile API.', 401,
            **{'WWW-Authenticate': 'Basic realm="Admin Mobile API"'})

    user_key = 'admin_api:user:' + hashed_key(username.lower())
    client_key = 'admin_api:client:' + anonymous_client_key()
    # Per-client lock only when the IP identifies the client (not behind an
    # onion service where it would be global); the per-username lock remains.
    use_client_lock = client_ip_is_meaningful()
    if (too_many_failures(user_key, ADMIN_API_USER_MAX_FAILURES, ADMIN_API_LOCKOUT_SECONDS)
            or (use_client_lock and too_many_failures(
                client_key, ADMIN_API_CLIENT_MAX_FAILURES, ADMIN_API_LOCKOUT_SECONDS))):
        return None, _admin_api_error(
            'Too many failed attempts. Try again later.', 429,
            **{'Retry-After': str(ADMIN_API_LOCKOUT_SECONDS)})

    user = User.query.filter_by(username=username, is_admin=True).first()
    try:
        password_ok = bcrypt.check_password_hash(
            user.password if user else _DUMMY_PASSWORD_HASH, password)
    except ValueError:
        password_ok = False
    if not user or not password_ok:
        record_failure(user_key)
        if use_client_lock:
            record_failure(client_key)
        return None, _admin_api_error(
            'Authentication required for admin mobile API.', 401,
            **{'WWW-Authenticate': 'Basic realm="Admin Mobile API"'})

    if user.is_banned:
        return None, _admin_api_error('This account has been suspended.', 403)
    if user.must_change_password:
        return None, _admin_api_error(
            'Password change required: sign in on the website first.', 403)
    if user.totp_enabled:
        # The code is sent on every stateless call: allow_reuse (about 90 s).
        if not _verify_totp_once(user, request.headers.get('X-TOTP-Code', ''),
                                 allow_reuse=True):
            record_failure(user_key)
            if use_client_lock:
                record_failure(client_key)
            return None, _admin_api_error(
                'A valid two-factor code is required in the X-TOTP-Code header.', 401,
                **{'WWW-Authenticate': 'Basic realm="Admin Mobile API"'})

    clear_failures(user_key)
    return user, None


def admin_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not _mobile_api_enabled():
            abort(404)
        admin_user, error = authenticate_admin_api()
        if error is not None:
            return error

        request.admin_api_user = admin_user
        return f(*args, **kwargs)

    return decorated_function


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
    content = str(payload.get('content') or '').strip()

    if not content:
        return jsonify({'error': 'Message content is required.'}), 400
    if len(content) > 5000:
        return jsonify({'error': 'Message too long.'}), 400

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
        if len(mobile_event_subscribers) >= 10:
            return jsonify({'error': 'Too many open streams.'}), 429
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
