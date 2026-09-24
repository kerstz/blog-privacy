"""Security regression tests.

Run:  pip install -r requirements.txt pytest && pytest -q tests/
Each test pins one fix of the 2026-09 security update (see SECURITY.md).
"""
import io
import os
import sys
import tempfile

import pytest

_TMP = tempfile.mkdtemp()
os.environ.update(
    SECRET_KEY='t' * 48,
    ENCRYPTION_KEY='k' * 32,
    ENCRYPTION_SALT='s' * 16,
    DATABASE_URL=f'sqlite:///{_TMP}/test.db',
)
for _k in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_ADMIN_CHAT_ID'):
    os.environ.pop(_k, None)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import pyotp  # noqa: E402
from PIL import Image  # noqa: E402

from app import app, db, bcrypt, socketio  # noqa: E402
from app.models import User, Post, Comment, Message, Donor  # noqa: E402
from app import utils  # noqa: E402

PASSWORD = 'Correct-Horse-42'


@pytest.fixture(autouse=True)
def fresh_db():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    utils._RATE_LIMIT_STORE.clear()
    with app.app_context():
        db.drop_all()
        db.create_all()
        pw = bcrypt.generate_password_hash(PASSWORD).decode()
        for name, is_admin in (('admin', True), ('alice', False), ('bob', False)):
            db.session.add(User(username=name, password=pw, is_admin=is_admin))
        db.session.commit()
        db.session.add(Post(title='Public', content='<p>hello</p><script>alert(1)</script>',
                            author_id=1, is_published=True, is_draft=False))
        db.session.add(Post(title='SECRET-DRAFT', content='draft', author_id=1,
                            is_published=False, is_draft=True))
        db.session.commit()
    yield


def login(name):
    c = app.test_client()
    r = c.post('/login', data={'username': name, 'password': PASSWORD})
    assert r.status_code == 302
    return c


def uid(name):
    with app.app_context():
        return User.query.filter_by(username=name).first().id


# ---------------------------------------------------------------- XSS
def test_comment_bbcode_cannot_inject_html():
    a = login('alice')
    payload = '[url=https://x" onmouseover="alert(1)]x[/url] <script>alert(2)</script> [img]javascript:alert(3)[/img]'
    a.post('/post/1', data={'content': payload})
    html = login('bob').get('/post/1').data
    assert b'<script>alert(2)' not in html
    assert b'onmouseover="alert' not in html
    assert b'javascript:alert' not in html


def test_reply_cannot_inject_html():
    a = login('alice')
    a.post('/post/1', data={'content': 'parent'})
    a.post('/reply_to_comment/1/1', data={'content': '<svg onload=alert(1)><img src=x onerror=alert(2)>'})
    html = login('bob').get('/post/1').data
    assert b'onload=alert' not in html and b'onerror' not in html


def test_bbcode_still_renders():
    a = login('alice')
    a.post('/post/1', data={'content': '[b]bold[/b] [url=https://example.org]link[/url]'})
    html = a.get('/post/1').data
    assert b'<strong>bold</strong>' in html
    assert b'href="https://example.org"' in html


def test_post_content_is_sanitized():
    html = app.test_client().get('/post/1').data
    assert b'<p>hello</p>' in html
    assert b'<script>alert(1)' not in html


def test_chat_message_is_escaped():
    a = login('alice')
    a.post('/chat', data={'message': '<img src=x onerror=alert(1)>'})
    assert b'<img src=x onerror' not in a.get('/chat').data
    assert b'<img src=x onerror' not in login('admin').get('/admin/chat').data


def test_username_charset_enforced():
    c = app.test_client()
    r = c.post('/register', data={'username': "x');alert(1);//", 'password': 'a-long-password-1',
                                   'confirm_password': 'a-long-password-1'})
    assert r.status_code == 200  # form re-rendered with an error
    with app.app_context():
        assert User.query.count() == 3


def test_weak_password_rejected():
    c = app.test_client()
    c.post('/register', data={'username': 'carol', 'password': 'short', 'confirm_password': 'short'})
    with app.app_context():
        assert not User.query.filter_by(username='carol').first()


# ---------------------------------------------------------------- privacy / access control
def test_users_cannot_read_each_others_chat():
    login('alice').post('/chat', data={'message': 'alice-private'})
    assert b'alice-private' not in login('bob').get('/chat').data
    assert b'alice-private' in login('alice').get('/chat').data


def test_chat_messages_encrypted_at_rest():
    login('alice').post('/chat', data={'message': 'plaintext-secret'})
    with app.app_context():
        m = Message.query.first()
        assert 'plaintext-secret' not in m.content
        assert m.get_decrypted_content() == 'plaintext-secret'


def test_drafts_hidden_from_public():
    anon = app.test_client()
    assert b'SECRET-DRAFT' not in anon.get('/').data
    assert b'SECRET-DRAFT' not in anon.get('/posts').data
    assert anon.get('/post/2').status_code == 404
    assert login('admin').get('/post/2').status_code == 200


def test_draft_not_auto_published():
    app.test_client().get('/')
    with app.app_context():
        assert db.session.get(Post, 2).is_published is False


def _png_with_gps():
    import piexif
    img = Image.new('RGB', (20, 20), 'red')
    exif = piexif.dump({'GPS': {piexif.GPSIFD.GPSLatitudeRef: b'N'}, '0th': {piexif.ImageIFD.Make: b'SpyCam'}})
    buf = io.BytesIO()
    img.save(buf, 'JPEG', exif=exif)
    buf.seek(0)
    return buf


def test_upload_access_control_and_exif_strip():
    a = login('alice')
    a.post('/chat', data={'message': '', 'file': (_png_with_gps(), 'holiday.jpg')},
           content_type='multipart/form-data')
    with app.app_context():
        m = Message.query.first()
        path = m.file_path
    name = path.split('/')[-1]
    assert 'holiday' not in name  # random name, no user filename on disk
    assert name.endswith('.webp')
    with Image.open(path) as img:
        assert not img.info.get('exif')
    assert a.get(f'/uploads/{name}').status_code == 200
    assert login('admin').get(f'/uploads/{name}').status_code == 200
    assert login('bob').get(f'/uploads/{name}').status_code == 404
    assert app.test_client().get(f'/uploads/{name}').status_code == 404
    os.remove(path)


def test_svg_upload_rejected():
    a = login('alice')
    svg = io.BytesIO(b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')
    a.post('/chat', data={'message': '', 'file': (svg, 'x.svg')}, content_type='multipart/form-data')
    with app.app_context():
        assert Message.query.count() == 0


# ---------------------------------------------------------------- auth
def test_login_is_rate_limited():
    c = app.test_client()
    for _ in range(5):
        c.post('/login', data={'username': 'alice', 'password': 'wrong-password'})
    r = c.post('/login', data={'username': 'alice', 'password': PASSWORD})
    assert r.status_code == 302 and '/login' not in r.headers['Location'] or b'Welcome' not in r.data
    with c.session_transaction() as s:
        assert '_user_id' not in s


def test_totp_bruteforce_limited_and_no_replay():
    secret = pyotp.random_base32()
    with app.app_context():
        u = User.query.filter_by(username='alice').first()
        u.totp_secret, u.totp_enabled = secret, True
        db.session.commit()
    c = app.test_client()
    c.post('/login', data={'username': 'alice', 'password': PASSWORD})
    for _ in range(5):
        c.post('/login/totp', data={'code': '000000'})
    c.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    with c.session_transaction() as s:
        assert '_user_id' not in s  # locked out after 5 failures

    utils._RATE_LIMIT_STORE.clear()
    code = pyotp.TOTP(secret).now()
    c1 = app.test_client()
    c1.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c1.post('/login/totp', data={'code': code})
    with c1.session_transaction() as s:
        assert s.get('_user_id') == str(uid('alice'))
    c2 = app.test_client()
    c2.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c2.post('/login/totp', data={'code': code})  # replay of the same code
    with c2.session_transaction() as s:
        assert '_user_id' not in s


def test_mobile_api_requires_totp_when_enabled():
    import base64
    hdr = {'Authorization': 'Basic ' + base64.b64encode(f'admin:{PASSWORD}'.encode()).decode()}
    c = app.test_client()
    assert c.get('/api/admin/mobile/ping', headers=hdr).status_code == 200
    secret = pyotp.random_base32()
    with app.app_context():
        u = User.query.filter_by(username='admin').first()
        u.totp_secret, u.totp_enabled = secret, True
        db.session.commit()
    assert c.get('/api/admin/mobile/ping', headers=hdr).status_code == 401
    hdr['X-TOTP-Code'] = pyotp.TOTP(secret).now()
    assert c.get('/api/admin/mobile/ping', headers=hdr).status_code == 200


def test_mobile_api_bruteforce_limited():
    import base64
    bad = {'Authorization': 'Basic ' + base64.b64encode(b'admin:nope').decode()}
    good = {'Authorization': 'Basic ' + base64.b64encode(f'admin:{PASSWORD}'.encode()).decode()}
    c = app.test_client()
    for _ in range(10):
        c.get('/api/admin/mobile/ping', headers=bad)
    assert c.get('/api/admin/mobile/ping', headers=good).status_code == 401


def test_socketio_rejects_anonymous_and_does_not_broadcast():
    anon = socketio.test_client(app)
    assert not anon.is_connected()
    a_http, b_http = login('alice'), login('bob')
    a = socketio.test_client(app, flask_test_client=a_http)
    b = socketio.test_client(app, flask_test_client=b_http)
    a.emit('message', {'msg': 'socket-secret', 'sender_id': 3, 'receiver_id': 3})
    assert all('socket-secret' not in str(ev) for ev in b.get_received())
    with app.app_context():
        m = Message.query.first()
        assert m.sender_id == uid('alice')  # client-supplied sender_id ignored


# ---------------------------------------------------------------- admin / functional
def test_cannot_delete_or_demote_last_admin():
    adm = login('admin')
    adm.post(f"/demote_user/{uid('admin')}")
    adm.post(f"/delete_user/{uid('admin')}")
    with app.app_context():
        assert User.query.filter_by(is_admin=True).count() == 1


def test_delete_user_with_content_works():
    a = login('alice')
    a.post('/post/1', data={'content': 'hi'})
    a.post('/chat', data={'message': 'hello'})
    r = login('admin').post(f"/delete_user/{uid('alice')}")
    assert r.status_code == 302
    with app.app_context():
        assert not User.query.filter_by(username='alice').first()
        assert Message.query.count() == 0
        assert Comment.query.first().author_id is None


def test_non_admin_cannot_use_admin_routes():
    b = login('bob')
    for url in ('/manage_users', '/admin/chat', '/manage_posts', '/admin_dashboard'):
        assert b.get(url).status_code == 302
    b.post(f"/promote_user/{uid('bob')}")
    with app.app_context():
        assert not User.query.filter_by(username='bob').first().is_admin


def test_donation_cannot_be_forged():
    for c in (app.test_client(), login('bob')):
        c.post('/donate', data={'amount': 'inf'})
        c.post('/donate', data={'amount': '99999'})
    with app.app_context():
        assert Donor.query.count() == 0


def test_pages_and_banners_admin_work():
    adm = login('admin')
    assert adm.post('/create_page', data={'title': 'About Us', 'content': 'x'}).status_code == 302
    assert adm.get('/manage_pages').status_code == 200
    assert app.test_client().get('/page/about-us').status_code == 200
    adm.post('/manage_banners', data={'title': 'Ban', 'content': 'c', 'image_url': 'https://e.org/a.png',
                                      'link_url': 'javascript://x/%0aalert(1)', 'position': 'header'})
    from app.models import Banner
    with app.app_context():
        assert Banner.query.count() == 0


def test_security_headers():
    r = app.test_client().get('/')
    csp = r.headers['Content-Security-Policy']
    assert "'unsafe-eval'" not in csp
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert login('alice').get('/chat').headers.get('Cache-Control') == 'no-store'


def test_open_redirect_blocked_in_rate_limiter():
    c = app.test_client()
    for _ in range(6):
        r = c.post('/login', data={'username': 'x', 'password': 'y'}, headers={'Referer': 'https://evil.example/'})
    assert 'evil.example' not in r.headers.get('Location', '')
