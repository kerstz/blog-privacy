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
    SECURITY_STATE_DB=f'{_TMP}/security_state.db',
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
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, ANTISPAM_ENABLED=False)
    utils.reset_security_state()
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
    assert name.endswith('.webp.enc')  # re-encoded to WebP, then encrypted at rest
    with open(path, 'rb') as f:
        raw = f.read()
    assert b'WEBP' not in raw[:64] and b'SpyCam' not in raw  # unreadable on disk
    from app.services import read_upload_bytes
    with Image.open(io.BytesIO(read_upload_bytes(path))) as img:
        assert img.format == 'WEBP'
        assert not img.info.get('exif')
    r = a.get(f'/uploads/{name}')
    assert r.status_code == 200 and r.mimetype == 'image/webp' and r.data[8:12] == b'WEBP'
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

    utils.reset_security_state()
    code = pyotp.TOTP(secret).now()
    c1 = app.test_client()
    c1.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c1.post('/login/totp', data={'code': code})
    with c1.session_transaction() as s:
        assert s.get('_user_id') == f"{uid('alice')}:0"
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


# ---------------------------------------------------------------- privacy release (no JS, no third parties)
PUBLIC_PAGES = ('/', '/posts', '/post/1', '/about', '/contact', '/donate', '/editor_help', '/login', '/register')


def test_no_javascript_anywhere():
    anon, alice, admin = app.test_client(), login('alice'), login('admin')
    pages = [(anon, u) for u in PUBLIC_PAGES] + [(alice, '/chat'), (alice, '/edit_profile')] + \
        [(admin, u) for u in ('/admin_dashboard', '/manage_posts', '/manage_users', '/manage_comments',
                              '/admin/chat', f"/admin/chat/{uid('alice')}", '/edit_post/1', '/manage_banners')]
    for client, url in pages:
        r = client.get(url)
        assert r.status_code == 200, url
        html = r.data.decode()
        assert '<script' not in html, url
        assert 'onclick=' not in html, url
        assert "script-src 'none'" in r.headers['Content-Security-Policy']


def test_no_third_party_resources():
    for url in PUBLIC_PAGES:
        html = app.test_client().get(url).data.decode()
        for host in ('googleapis', 'gstatic', 'cdn.', 'cloudflare', 'bootstrapcdn', '<iframe'):
            assert host not in html, (url, host)


def test_external_images_become_links():
    a = login('alice')
    a.post('/post/1', data={'content': '[img]https://tracker.example/pixel.png[/img]'})
    html = a.get('/post/1').data.decode()
    assert '<img src="https://tracker.example' not in html
    assert 'href="https://tracker.example/pixel.png"' in html
    with app.app_context():
        db.session.get(Post, 1).content = '<p>x</p><img src="https://tracker.example/p.png">'
        db.session.commit()
    assert 'src="https://tracker.example' not in a.get('/post/1').data.decode()


def test_donate_page_has_server_side_qr_codes():
    html = app.test_client().get('/donate').data.decode()
    assert html.count('src="data:image/png;base64,') >= 8


def test_comment_filter_is_server_side():
    a = login('alice')
    a.post('/post/1', data={'content': 'fresh comment'})
    adm = login('admin')
    assert b'fresh comment' in adm.get('/manage_comments?filter=recent').data
    assert b'fresh comment' not in adm.get('/manage_comments?filter=popular').data


def test_delete_post_works_with_csrf():
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        adm = app.test_client()
        page = adm.get('/login').data.decode()
        import re as _re
        token = _re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', page).group(1)
        adm.post('/login', data={'username': 'admin', 'password': PASSWORD, 'csrf_token': token})
        page = adm.get('/manage_posts').data.decode()
        token = _re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        adm.post('/delete_post/2', data={'csrf_token': token})
        with app.app_context():
            assert db.session.get(Post, 2) is None
    finally:
        app.config['WTF_CSRF_ENABLED'] = False


def test_totp_works_when_server_is_not_utc():
    import time as _time
    old = os.environ.get('TZ')
    os.environ['TZ'] = 'Pacific/Kiritimati'  # UTC+14
    _time.tzset()
    try:
        from app.services import _verify_totp_once
        secret = pyotp.random_base32()
        with app.app_context():
            u = User.query.filter_by(username='alice').first()
            u.totp_secret, u.totp_enabled = secret, True
            db.session.commit()
            assert _verify_totp_once(u, pyotp.TOTP(secret).now())
    finally:
        if old is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = old
        _time.tzset()


def test_rate_limit_is_persistent():
    for _ in range(3):
        utils.hit_rate_limit('persist-test', 3, 60)
    utils._state_local.conn.close()
    utils._state_local.conn = None  # simulate a new process / restart
    assert utils.hit_rate_limit('persist-test', 3, 60)


def test_onion_location_header():
    from app import routes
    old = routes.ONION_ADDRESS
    routes.ONION_ADDRESS = 'a' * 56 + '.onion'
    try:
        r = app.test_client().get('/about')
        assert r.headers['Onion-Location'] == f"http://{'a' * 56}.onion/about"
    finally:
        routes.ONION_ADDRESS = old


# ---------------------------------------------------------------- account security release
def _enable_2fa(name):
    from app.services import generate_recovery_codes
    secret = pyotp.random_base32()
    with app.app_context():
        u = User.query.filter_by(username=name).first()
        u.totp_secret, u.totp_enabled = secret, True
        codes = generate_recovery_codes(u)
        db.session.commit()
    return secret, codes


def _logged_in(client):
    with client.session_transaction() as s:
        return '_user_id' in s


def test_change_password_logs_out_other_sessions():
    phone, laptop = login('alice'), login('alice')
    r = laptop.post('/account/password', data={'current_password': PASSWORD,
                                               'new_password': 'Brand-New-Pass-99',
                                               'confirm_password': 'Brand-New-Pass-99'})
    assert r.status_code == 302
    assert laptop.get('/chat').status_code == 200          # current browser stays logged in
    assert phone.get('/chat').status_code == 302            # stolen/other session is dead
    c = app.test_client()
    c.post('/login', data={'username': 'alice', 'password': 'Brand-New-Pass-99'})
    assert _logged_in(c)


def test_change_password_requires_current_password():
    a = login('alice')
    a.post('/account/password', data={'current_password': 'wrong-password-x',
                                      'new_password': 'Brand-New-Pass-99', 'confirm_password': 'Brand-New-Pass-99'})
    c = app.test_client()
    c.post('/login', data={'username': 'alice', 'password': PASSWORD})
    assert _logged_in(c)


def test_logout_everywhere():
    phone, laptop = login('alice'), login('alice')
    laptop.post('/account/logout-everywhere')
    assert laptop.get('/chat').status_code == 200
    assert phone.get('/chat').status_code == 302


def test_logout_requires_post():
    a = login('alice')
    assert a.get('/logout').status_code == 405
    a.post('/logout')
    assert not _logged_in(a)


def test_recovery_code_login_single_use():
    _, codes = _enable_2fa('alice')
    c = app.test_client()
    c.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c.post('/login/totp', data={'code': codes[0]})
    assert _logged_in(c)
    c2 = app.test_client()
    c2.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c2.post('/login/totp', data={'code': codes[0]})     # already used
    assert not _logged_in(c2)
    with app.app_context():
        from app.services import recovery_codes_left
        assert recovery_codes_left(User.query.filter_by(username='alice').first()) == 9
        assert codes[1] not in (User.query.filter_by(username='alice').first().recovery_codes or '')


def test_recovery_codes_shown_once_when_enabling_2fa():
    a = login('alice')
    a.get('/totp/setup')
    with a.session_transaction() as s:
        secret = s['totp_pending_secret']
    html = a.post('/totp/setup', data={'code': pyotp.TOTP(secret).now()}).data.decode()
    import re as _re
    shown = _re.findall(r'<span>([A-Z0-9]{5}-[A-Z0-9]{5})</span>', html)
    assert len(shown) == 10
    with app.app_context():
        stored = User.query.filter_by(username='alice').first().recovery_codes
        assert all(code not in stored for code in shown)   # only hashes stored


def test_export_my_data_requires_password_and_decrypts():
    a = login('alice')
    a.post('/chat', data={'message': 'my secret message'})
    assert a.post('/account/export', data={'ex-password': 'nope-nope-nope'}).status_code == 200
    r = a.post('/account/export', data={'ex-password': PASSWORD})
    assert r.mimetype == 'application/json' and 'attachment' in r.headers['Content-Disposition']
    data = r.get_json()
    assert data['account']['username'] == 'alice'
    assert data['messages'][0]['content'] == 'my secret message'
    assert '$2b$' not in r.data.decode()   # no password hash in the export


def test_export_requires_2fa_code_when_enabled():
    secret, _ = _enable_2fa('alice')
    c = app.test_client()
    c.post('/login', data={'username': 'alice', 'password': PASSWORD})
    c.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    r = c.post('/account/export', data={'ex-password': PASSWORD})
    assert r.mimetype != 'application/json'


def test_delete_own_account():
    a = login('alice')
    a.post('/post/1', data={'content': 'bye'})
    a.post('/chat', data={'message': 'private'})
    a.post('/account/delete', data={'del-password': PASSWORD, 'del-confirm': 'delete'})  # wrong confirm
    with app.app_context():
        assert User.query.filter_by(username='alice').first()
    a.post('/account/delete', data={'del-password': PASSWORD, 'del-confirm': 'DELETE'})
    with app.app_context():
        assert not User.query.filter_by(username='alice').first()
        assert Message.query.count() == 0
        assert Comment.query.first().author_id is None
    assert not _logged_in(a)


def test_last_admin_cannot_delete_own_account():
    adm = login('admin')
    adm.post('/account/delete', data={'del-password': PASSWORD, 'del-confirm': 'DELETE'})
    with app.app_context():
        assert User.query.filter_by(username='admin').first()


def test_security_alerts_sent(monkeypatch):
    from app import services
    sent = []
    monkeypatch.setattr(services.app.logger, 'warning', lambda fmt, *a: sent.append(fmt % a if a else fmt))
    login('admin')
    app.test_client().post('/login', data={'username': 'admin', 'password': 'wrong-password'})
    assert any('admin login' in m for m in sent)
    assert any('failed login on admin' in m for m in sent)


def test_encrypt_legacy_command(tmp_path):
    from app.encryption import message_encryption
    legacy_file = os.path.join('uploads', 'legacy_test_file.txt')
    with open(legacy_file, 'w') as f:
        f.write('old plaintext attachment')
    with app.app_context():
        db.session.add(Message(sender_id=uid('alice'), receiver_id=uid('admin'), content='old plaintext',
                               file_path='uploads/legacy_test_file.txt', file_type='file'))
        db.session.commit()
    runner = app.test_cli_runner()
    assert 'Encrypted 1 legacy message(s) and 1 file(s)' in runner.invoke(args=['encrypt-legacy']).output
    assert 'Encrypted 0 legacy message(s) and 0 file(s)' in runner.invoke(args=['encrypt-legacy']).output
    with app.app_context():
        m = Message.query.first()
        assert message_encryption.is_ciphertext(m.content) and m.get_decrypted_content() == 'old plaintext'
        assert m.file_path.endswith('.enc') and not os.path.exists(legacy_file)
        from app.services import read_upload_bytes
        assert read_upload_bytes(m.file_path) == b'old plaintext attachment'
        os.remove(m.file_path)


def test_antispam_honeypot_and_timing():
    app.config['ANTISPAM_ENABLED'] = True
    try:
        from app.forms import _new_antispam_token
        with app.test_request_context():
            fresh = _new_antispam_token()
        data = {'username': 'spambot', 'password': 'a-long-password-1', 'confirm_password': 'a-long-password-1'}
        c = app.test_client()
        c.post('/register', data={**data, 'form_ts': fresh})                    # too fast
        c.post('/register', data={**data})                                      # no token
        import time as _time
        with app.test_request_context():
            import itsdangerous
            s = itsdangerous.URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='antispam-form')
            old = s.dumps(int(_time.time()) - 10)
        c.post('/register', data={**data, 'form_ts': old, 'website': 'http://spam'})  # honeypot filled
        with app.app_context():
            assert not User.query.filter_by(username='spambot').first()
        c.post('/register', data={**data, 'form_ts': old})                      # human
        with app.app_context():
            assert User.query.filter_by(username='spambot').first()
    finally:
        app.config['ANTISPAM_ENABLED'] = False


def test_new_post_can_be_published_with_category_and_tags():
    adm = login('admin')
    adm.post('/manage_posts', data={'title': 'Tagged post', 'content': 'hello', 'is_published': 'y',
                                    'category': 'Privacy', 'tags': 'Tor, linux, tor'})
    with app.app_context():
        p = Post.query.filter_by(title='Tagged post').first()
        assert p.is_published and p.category == 'Privacy'
        assert sorted(t.slug for t in p.tags) == ['linux', 'tor']
    anon = app.test_client()
    assert b'Tagged post' in anon.get('/tag/tor').data
    assert b'Tagged post' in anon.get('/category/privacy').data
    assert b'Tagged post' in anon.get('/search?q=tagged').data
    assert b'SECRET-DRAFT' not in anon.get('/search?q=SECRET').data
    feed = anon.get('/feed.xml')
    assert feed.mimetype == 'application/rss+xml' and b'Tagged post' in feed.data and b'SECRET-DRAFT' not in feed.data


def test_edit_post_can_unpublish_and_publish():
    adm = login('admin')
    adm.post('/edit_post/1', data={'title': 'Public', 'content': 'x'})       # checkbox unticked
    assert app.test_client().get('/post/1').status_code == 404
    adm.post('/edit_post/1', data={'title': 'Public', 'content': 'x', 'is_published': 'y'})
    assert app.test_client().get('/post/1').status_code == 200


def test_search_wildcards_are_literal():
    html = app.test_client().get('/search?q=%25%25').data.decode()
    assert 'Public' not in html   # "%%" must not match every post


def test_strict_style_csp():
    r = login('admin').get('/manage_posts')
    csp = r.headers['Content-Security-Policy']
    assert "style-src 'self';" in csp and "'unsafe-inline'" not in csp.split('style-src-attr')[0]
    assert '<style' not in r.data.decode()
