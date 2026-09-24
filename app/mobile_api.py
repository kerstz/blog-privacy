"""Mobile admin REST API (HTTP Basic Auth + TOTP header, SSE event stream)."""
from flask import request, jsonify, Response, stream_with_context
from app import app, db, csrf
from app.models import User, Message
from app.utils import hit_rate_limit
from functools import wraps
from datetime import datetime
import json
import base64
import queue
from app.services import (
    _check_user_password,
    _verify_totp_once,
    mobile_event_lock,
    mobile_event_subscribers,
    publish_mobile_event,
    serialize_chat_message,
)


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

    # Brute-force protection (per IP and per account), failures only.
    ip_key = f"api_fail_ip:{request.remote_addr}"
    user_key = f"api_fail_user:{username.lower()}"
    if hit_rate_limit(ip_key, 10, 900, record=False) or hit_rate_limit(user_key, 10, 900, record=False):
        return None

    user = User.query.filter_by(username=username, is_admin=True).first()
    ok = _check_user_password(user, password)
    # 2FA is enforced on the API too: accounts with TOTP must send the current
    # code in the X-TOTP-Code header (Basic Auth alone bypassed 2FA before).
    if ok and user.totp_enabled:
        ok = _verify_totp_once(user, request.headers.get('X-TOTP-Code', ''), allow_reuse=True)
    if not ok:
        hit_rate_limit(ip_key, 10, 900)
        hit_rate_limit(user_key, 10, 900)
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
