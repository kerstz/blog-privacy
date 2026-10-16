"""Tests of the 2026-10-16 audit fixes (agent A)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_security_fixes import (PASSWORD, app, authed_page, basic, make_user,  # noqa: E402
                                 reset, sign_in)
from app import routes, utils  # noqa: E402


def client_from(ip):
    client = app.test_client()
    client.environ_base['REMOTE_ADDR'] = ip
    return client


def _bad(client, name, n):
    for _ in range(n):
        client.post('/login', data={'username': name, 'password': 'wrong-password-1'})


# ------------------------------------------------------------- H1

def test_loopback_anonymous_failures_do_not_lock_other_users():
    reset()
    make_user('alice')
    make_user('boss', admin=True)
    attacker = app.test_client()
    _bad(attacker, 'nobody', 8)
    for name in ('alice', 'boss'):
        client, resp = sign_in(name)
        assert resp.status_code == 302, name
        assert authed_page(client)


def test_username_lock_still_applies_on_loopback():
    reset()
    make_user('victim')
    client = app.test_client()
    _bad(client, 'victim', 10)
    _, resp = sign_in('victim', client=client)
    assert resp.status_code == 200
    assert not authed_page(client)


def test_client_lock_still_applies_with_real_ip():
    reset()
    make_user('alice')
    attacker = client_from('203.0.113.7')
    for i in range(5):
        attacker.post('/login', data={'username': f'ghost{i}', 'password': 'wrong-password-1'})
    _, resp = sign_in('alice', client=attacker)
    assert resp.status_code == 200 and not authed_page(attacker)
    other = client_from('203.0.113.8')
    _, resp = sign_in('alice', client=other)
    assert resp.status_code == 302


def test_client_ip_is_meaningful():
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert not utils.client_ip_is_meaningful()
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '::1'}):
        assert not utils.client_ip_is_meaningful()
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '198.51.100.1'}):
        assert utils.client_ip_is_meaningful()
    app.config['TRUSTED_PROXY_COUNT'] = 1
    try:
        with app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            assert utils.client_ip_is_meaningful()
    finally:
        app.config['TRUSTED_PROXY_COUNT'] = 0


def test_login_rate_limit_is_per_username_on_loopback():
    reset()
    make_user('alice')
    client = app.test_client()
    # 30 posts for one pseudo exhaust its rate limit...
    for _ in range(31):
        client.post('/login', data={'username': 'spam', 'password': 'x'})
    # ... but another pseudo is unaffected.
    _, resp = sign_in('alice')
    assert resp.status_code == 302


def test_mobile_api_client_lock_not_global_on_loopback():
    reset()
    make_user('boss', admin=True)
    attacker = app.test_client()
    for i in range(35):
        attacker.get('/api/admin/mobile/ping', headers=basic(f'ghost{i}', 'bad-password-xx'))
    resp = app.test_client().get('/api/admin/mobile/ping', headers=basic('boss', PASSWORD))
    assert resp.status_code != 429


def test_flask_unlock_command():
    reset()
    make_user('victim')
    client = app.test_client()
    _bad(client, 'victim', 10)
    _, resp = sign_in('victim', client=client)
    assert not authed_page(client)
    result = app.test_cli_runner().invoke(args=['unlock', 'victim'])
    assert result.exit_code == 0, result.output
    client, resp = sign_in('victim')
    assert resp.status_code == 302


def test_flask_unlock_all():
    reset()
    utils.record_failure(routes._login_failure_key('x'))
    result = app.test_cli_runner().invoke(args=['unlock', '--all'])
    assert result.exit_code == 0
    assert not utils.too_many_failures(routes._login_failure_key('x'), 1, 900)


def test_shared_anonymous_ceiling_is_high_on_loopback():
    reset()
    client = app.test_client()
    from app.models import User
    for i in range(12):
        client.post('/register', data={'username': f'user{i}', 'password': PASSWORD + str(i),
                                       'confirm_password': PASSWORD + str(i)})
    with app.app_context():
        assert User.query.count() == 12


# ------------------------------------------------------------- H3

def _contact(name='Ann', email='ann@example.org', message='hello <b>x</b>', days_old=0, read=False):
    from datetime import datetime, timedelta
    from app import db
    from app.models import ContactMessage
    with app.app_context():
        m = ContactMessage(name=name, email=email, message=message, is_read=read,
                           timestamp=datetime.utcnow() - timedelta(days=days_old))
        db.session.add(m)
        db.session.commit()
        return m.id


def _admin_client():
    make_user('boss', admin=True)
    client, resp = sign_in('boss')
    assert resp.status_code == 302
    return client


def test_admin_contact_requires_admin():
    reset()
    make_user('alice')
    mid = _contact()
    anon = app.test_client()
    assert anon.get('/admin/contact').status_code == 302
    client, _ = sign_in('alice')
    assert client.get('/admin/contact').status_code == 302
    assert client.post(f'/admin/contact/{mid}/delete').status_code == 302
    from app.models import ContactMessage
    with app.app_context():
        assert ContactMessage.query.count() == 1


def test_admin_contact_list_read_delete():
    reset()
    keep = _contact(name='Keep', message='first')
    done = _contact(name='Done', message='second', read=True)
    client = _admin_client()
    html = client.get('/admin/contact').get_data(as_text=True)
    assert 'Keep' in html
    xss = _contact(message='<script>alert(1)</script>')
    html = client.get('/admin/contact').get_data(as_text=True)
    assert '<script>alert(1)' not in html and '&lt;script&gt;' in html
    client.post(f'/admin/contact/{xss}/delete')
    from app.models import ContactMessage
    assert client.post(f'/admin/contact/{keep}/read').status_code == 302
    with app.app_context():
        assert ContactMessage.query.get(keep).is_read is True
    client.post('/admin/contact/delete-read')
    with app.app_context():
        assert ContactMessage.query.count() == 0
    again = _contact()
    client.post(f'/admin/contact/{again}/delete')
    with app.app_context():
        assert ContactMessage.query.count() == 0
    assert done


def test_dashboard_links_to_admin_contact():
    reset()
    _contact()
    client = _admin_client()
    assert '/admin/contact' in client.get('/admin_dashboard').get_data(as_text=True)


def test_purge_contact_command():
    reset()
    _contact(days_old=100)
    _contact(days_old=5)
    from app.models import ContactMessage
    result = app.test_cli_runner().invoke(args=['purge-contact'])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert ContactMessage.query.count() == 1
    result = app.test_cli_runner().invoke(args=['purge-contact', '--days', '1'])
    with app.app_context():
        assert ContactMessage.query.count() == 0


def test_contact_email_optional():
    reset()
    from app.models import ContactMessage
    client = app.test_client()
    resp = client.post('/contact', data={'name': 'Bob', 'email': '', 'message': 'hi'})
    assert resp.status_code == 302
    with app.app_context():
        m = ContactMessage.query.one()
        assert m.email == '' and m.name == 'Bob'


# ------------------------------------------------------------- M1

def _gradient_png():
    import io
    from PIL import Image
    img = Image.new('RGB', (64, 64))
    img.putdata([((x * 4) % 256, (y * 4) % 256, ((x * y) // 3) % 256)
                 for y in range(64) for x in range(64)])
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf


def test_flag_image_hashes_plaintext_and_blocks_reupload():
    import hashlib
    from app.models import BlockedImageHash, Message, User
    from app.services import read_upload_bytes
    reset()
    make_user('boss', admin=True)
    make_user('mallory')
    make_user('eve')
    mal, _ = sign_in('mallory')
    mal.post('/chat', data={'message': '', 'file': (_gradient_png(), 'a.png')},
             content_type='multipart/form-data')
    with app.app_context():
        msg = Message.query.filter(Message.file_path.isnot(None)).one()
        mid, path = msg.id, msg.file_path
        plain = read_upload_bytes(path)
    boss, _ = sign_in('boss')
    assert boss.post(f'/admin/flag_image/{mid}').status_code == 302
    with app.app_context():
        entry = BlockedImageHash.query.one()
        assert entry.sha256 == hashlib.sha256(plain).hexdigest()
        assert entry.dhash is not None
        assert User.query.filter_by(username='mallory').one().is_banned
    eve, _ = sign_in('eve')
    eve.post('/chat', data={'message': '', 'file': (_gradient_png(), 'b.png')},
             content_type='multipart/form-data')
    with app.app_context():
        assert User.query.filter_by(username='eve').one().is_banned
        assert Message.query.filter(Message.sender_id == User.query.filter_by(
            username='eve').one().id, Message.file_path.isnot(None)).count() == 0


# ------------------------------------------------------------- M2

def test_socketio_endpoint_is_gone():
    client = app.test_client()
    assert client.get('/socket.io/?EIO=4&transport=polling').status_code == 404
    assert client.post('/socket.io/?EIO=4&transport=polling').status_code in (404, 405)


def test_app_does_not_import_socketio():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for path in list((root / 'app').glob('*.py')) + [root / 'wsgi.py']:
        text = path.read_text(encoding='utf-8')
        assert 'flask_socketio' not in text and 'import socketio' not in text, path.name


# ------------------------------------------------------------- M3

def _totp_admin(name='boss'):
    import pyotp
    from app import db
    from app.models import User
    make_user(name, admin=True)
    secret = pyotp.random_base32()
    with app.app_context():
        user = User.query.filter_by(username=name).one()
        routes._store_totp_secret(user, secret)
        user.totp_enabled = True
        db.session.commit()
    return pyotp.TOTP(secret)


def _stream_closes_after(mutate):
    from app import mobile_api, db
    from app.models import User
    reset()
    totp = _totp_admin()
    client = app.test_client()
    old = mobile_api.SSE_HEARTBEAT_SECONDS
    mobile_api.SSE_HEARTBEAT_SECONDS = 0.05
    try:
        resp = client.get('/api/admin/mobile/stream',
                          headers={**basic('boss', PASSWORD), 'X-TOTP-Code': totp.now()},
                          buffered=False)
        assert resp.status_code == 200
        chunks = iter(resp.response)
        assert b'connected' in next(chunks)
        assert b'heartbeat' in next(chunks)   # still authorized
        with app.app_context():
            user = User.query.filter_by(username='boss').one()
            mutate(user)
            db.session.commit()
        for _ in range(10):  # the stream must end within a few heartbeats
            try:
                next(chunks)
            except StopIteration:
                return True
        return False
    finally:
        mobile_api.SSE_HEARTBEAT_SECONDS = old


def test_sse_closes_when_admin_banned():
    assert _stream_closes_after(lambda u: setattr(u, 'is_banned', True))


def test_sse_closes_when_admin_demoted():
    assert _stream_closes_after(lambda u: setattr(u, 'is_admin', False))


def test_sse_closes_when_session_version_changes():
    assert _stream_closes_after(lambda u: u.rotate_session_token())


def test_sse_closes_when_password_change_forced():
    assert _stream_closes_after(lambda u: setattr(u, 'must_change_password', True))


# ------------------------------------------------------------- M4

def test_mobile_api_off_by_default_env_unset():
    import os
    reset()
    _totp_admin()
    os.environ.pop('MOBILE_API_ENABLED', None)
    assert app.test_client().get('/api/admin/mobile/ping',
                                 headers=basic('boss', PASSWORD)).status_code == 404


# ------------------------------------------------------------- B7

def test_onion_location_header_survives_crlf_in_path():
    reset()
    old = routes.ONION_ADDRESS
    routes.ONION_ADDRESS = 'exampleexampleexample.onion'
    try:
        resp = app.test_client().get('/%0d%0aX-Evil:%201')
        assert resp.status_code in (200, 404)
        value = resp.headers['Onion-Location']
        assert '\r' not in value and '\n' not in value
        assert value.startswith('http://exampleexampleexample.onion/')
        assert '%0D%0A' in value.upper()
    finally:
        routes.ONION_ADDRESS = old


# ------------------------------------------------------------- B3

def test_change_password_requires_totp_when_enabled():
    reset()
    totp = _totp_admin('boss')
    client = app.test_client()
    # log in with password + code
    client.post('/login', data={'username': 'boss', 'password': PASSWORD})
    client.post('/login/totp', data={'code': totp.now()})
    data = {'current_password': PASSWORD, 'new_password': 'Brand-New-Pass-99',
            'confirm_password': 'Brand-New-Pass-99'}
    client.post('/account/password', data=data)       # no code
    from app.models import User
    from app import bcrypt
    with app.app_context():
        assert bcrypt.check_password_hash(User.query.filter_by(username='boss').one().password,
                                          PASSWORD)
    import time
    # a fresh code (the previous one was consumed by the login)
    code = totp.at(time.time() + 30)
    client.post('/account/password', data={**data, 'code': code})
    with app.app_context():
        assert bcrypt.check_password_hash(User.query.filter_by(username='boss').one().password,
                                          'Brand-New-Pass-99')
