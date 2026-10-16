"""Tests des correctifs de securite (audit du 2026-10-12).

    python -m pytest tests/test_security_fixes.py
    python tests/test_security_fixes.py        # sans pytest

Base SQLite en memoire, jamais instance/blog.db ; les fichiers d'upload vont
dans un dossier temporaire.
"""
import base64
import io
import os
import re
import sys
import tempfile
import time
import tracemalloc
from datetime import timedelta

os.environ['SECRET_KEY'] = 'test-secret-key-not-for-production'
os.environ['ENCRYPTION_KEY'] = 'test-encryption-key-not-for-production'
os.environ['ENCRYPTION_SALT'] = 'test-encryption-salt-not-for-production'
os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['SESSION_COOKIE_SECURE'] = '0'
# The rate limiter / failure counters are persistent (SQLite): keep them out of
# instance/ so a test run never touches the real state file. Under conftest the
# variable is already set and these are no-ops.
os.environ.setdefault('SECURITY_STATE_DB',
                      os.path.join(__import__('tempfile').mkdtemp(prefix='blog-tests-'), 's.db'))
os.environ.pop('MOBILE_API_ENABLED', None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from PIL import Image  # noqa: E402
from PIL.PngImagePlugin import PngInfo  # noqa: E402

from app import app, db, bcrypt  # noqa: E402
from app.models import (Comment, Donor, Like, Message, Notification, Post,  # noqa: E402
                        Revision, User)
from app import routes, utils  # noqa: E402
from app.encryption import message_encryption  # noqa: E402

app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False
app.config['ANTISPAM_ENABLED'] = False

PASSWORD = 'correct horse battery staple'


# ------------------------------------------------------------- outils

def reset():
    """Base vide + compteurs en memoire a zero."""
    ctx = app.app_context()
    ctx.push()
    db.session.remove()
    db.drop_all()
    db.create_all()
    ctx.pop()
    routes.action_rate_limit_buckets.clear()
    utils._RATE_LIMIT_STORE.clear()
    utils._FAILURE_STORE.clear()


def make_user(username, admin=False, **extra):
    with app.app_context():
        user = User(username=username, is_admin=admin, **extra)
        user.password = bcrypt.generate_password_hash(PASSWORD).decode()
        db.session.add(user)
        db.session.commit()
        return user.id


def make_post(author_id, published=True, scheduled=None, draft=False, title='Hello'):
    with app.app_context():
        post = Post(title=title, content='body [b]x[/b]', author_id=author_id,
                    is_published=published, scheduled_date=scheduled, is_draft=draft)
        db.session.add(post)
        db.session.commit()
        return post.id


def sign_in(username, password=PASSWORD, client=None):
    client = client or app.test_client()
    resp = client.post('/login', data={'username': username, 'password': password})
    return client, resp


def logged_in(username):
    client, resp = sign_in(username)
    assert resp.status_code == 302, resp.status_code
    return client


def basic(username, password):
    token = base64.b64encode(f'{username}:{password}'.encode()).decode()
    return {'Authorization': f'Basic {token}'}


def authed_page(client, path='/'):
    """Vrai si la session est reconnue (le menu propose la deconnexion)."""
    html = client.get(path).get_data(as_text=True)
    return '/logout' in html


# ------------------------------------------------------------- Fix 1 : XSS commentaires

LEGACY_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<a href="javascript:alert(1)" onclick="x()">k</a>',
    '<svg onload=alert(1)>',
    '<span style="background:url(javascript:alert(1))">s</span>',
]


def test_legacy_comment_rows_cannot_execute():
    reset()
    admin = make_user('admin', admin=True)
    post_id = make_post(admin)
    with app.app_context():
        for payload in LEGACY_PAYLOADS:
            db.session.add(Comment(content=payload, post_id=post_id, author_id=admin))
        # ligne ancienne "bien formee" : sortie de parse_bbcode
        db.session.add(Comment(content='<strong>gras</strong> &amp; <em>it</em>',
                               post_id=post_id, author_id=admin))
        db.session.commit()
    html = app.test_client().get(f'/post/{post_id}').get_data(as_text=True)
    low = html.lower()
    assert '<script>alert' not in low
    assert 'onerror' not in low
    assert 'onclick' not in low
    assert 'onload' not in low
    assert 'javascript:' not in low
    assert '<svg' not in low
    assert '<strong>gras</strong> &amp; <em>it</em>' in html  # mise en forme conservee
    # la ligne n'a pas ete reecrite
    with app.app_context():
        assert Comment.query.filter_by(content='<script>alert(1)</script>').count() == 1


def test_new_reply_and_edit_are_escaped():
    reset()
    admin = make_user('admin', admin=True)
    reader = make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        parent = Comment(content='root', content_format='bbcode', post_id=post_id,
                         author_id=admin)
        db.session.add(parent)
        db.session.commit()
        parent_id = parent.id
    client = logged_in('reader')

    resp = client.post(f'/reply_to_comment/{post_id}/{parent_id}',
                       data={'content': '<script>alert(1)</script> [b]x[/b]'})
    assert resp.status_code == 302
    html = client.get(f'/post/{post_id}').get_data(as_text=True)
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '<script>alert' not in html
    assert '<strong>x</strong>' in html

    with app.app_context():
        reply = Comment.query.filter(Comment.parent_id == parent_id).one()
        assert reply.content == '<script>alert(1)</script> [b]x[/b]'  # brut en base
        assert reply.content_format == 'bbcode'
        reply_id = reply.id

    resp = client.post(f'/edit_comment/{reply_id}/{post_id}',
                       data={'content': '<img src=x onerror=alert(2)>'})
    assert resp.status_code == 302
    html = client.get(f'/post/{post_id}').get_data(as_text=True)
    assert '<img src=x' not in html
    assert '&lt;img src=x onerror=alert(2)&gt;' in html


def test_empty_reply_and_edit_refused():
    reset()
    admin = make_user('admin', admin=True)
    make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        parent = Comment(content='root', content_format='bbcode', post_id=post_id,
                         author_id=admin)
        db.session.add(parent)
        db.session.commit()
        parent_id = parent.id
    client = logged_in('reader')
    client.post(f'/reply_to_comment/{post_id}/{parent_id}', data={'content': '   '})
    with app.app_context():
        assert Comment.query.count() == 1


def test_edit_prefill_of_legacy_row_is_text():
    reset()
    admin = make_user('admin', admin=True)
    post_id = make_post(admin)
    with app.app_context():
        c = Comment(content='<strong>a</strong> &amp; b<script>x</script>',
                    post_id=post_id, author_id=admin)
        db.session.add(c)
        db.session.commit()
        cid = c.id
    client = logged_in('admin')
    html = client.get(f'/edit_comment/{cid}/{post_id}').get_data(as_text=True)
    assert 'a &amp; bx' in html or 'a &amp; b' in html
    assert '<strong>' not in html
    with app.app_context():  # GET : rien d'ecrit
        assert Comment.query.get(cid).content_format is None


def test_post_content_rendered_without_orm_mutation():
    reset()
    admin = make_user('admin', admin=True)
    post_id = make_post(admin)
    anon = app.test_client()
    html = anon.get(f'/post/{post_id}').get_data(as_text=True)
    assert '<strong>x</strong>' in html
    with app.app_context():
        assert Post.query.get(post_id).content == 'body [b]x[/b]'


def test_sanitizer_unit():
    f = utils.sanitize_legacy_html
    assert f('<b onclick="x">a</b>') == 'a'
    assert f('<strong>a</strong>') == '<strong>a</strong>'
    assert f('<script>alert(1)</script>ok') == 'ok'
    assert f('a < b & c') == 'a &lt; b &amp; c'
    assert 'href="#"' in f('<a href="javascript:alert(1)">x</a>')
    assert 'href="https://e.org"' in f('<a href="https://e.org">x</a>')
    assert 'style=' not in f('<span style="x:expression(1)">a</span>')
    assert f('<strong>unclosed') == '<strong>unclosed</strong>'
    assert utils.html_to_text('<b>a</b>&amp;<script>x()</script>b') == 'a&b'


# ------------------------------------------------------------- Fix 2 : limiteur

def test_get_login_is_not_counted():
    reset()
    client = app.test_client()
    for _ in range(8):
        assert client.get('/login').status_code == 200


def test_login_lockout_per_username():
    reset()
    make_user('victim')
    client = app.test_client()
    for _ in range(10):
        resp = client.post('/login', data={'username': 'victim', 'password': 'wrong-password-1'})
        assert resp.status_code == 200
    # 11e : refuse meme avec le bon mot de passe
    resp = client.post('/login', data={'username': 'victim', 'password': PASSWORD})
    assert resp.status_code == 200
    assert not authed_page(client)
    # pseudo inexistant : meme comportement (pas d'enumeration)
    for _ in range(10):
        client.post('/login', data={'username': 'ghost', 'password': 'wrong-password-1'})
    html = client.post('/login', data={'username': 'ghost', 'password': 'x'}).get_data(as_text=True)
    assert 'Login failed' in html


def test_login_success_clears_failures():
    reset()
    make_user('alice')
    client = app.test_client()
    for _ in range(3):
        client.post('/login', data={'username': 'alice', 'password': 'wrong-password-1'})
    _, resp = sign_in('alice', client=client)
    assert resp.status_code == 302
    assert not utils.too_many_failures(routes._login_failure_key('alice'), 1, 900)


def test_rate_limit_referrer_is_same_site_only():
    reset()
    make_user('reader')
    client = logged_in('reader')
    admin = make_user('admin', admin=True)
    post_id = make_post(admin)
    for _ in range(20):
        client.post(f'/like_post/{post_id}')
    resp = client.post(f'/like_post/{post_id}', headers={'Referer': 'https://evil.example/x'})
    assert resp.status_code == 302
    assert resp.headers['Location'].startswith('/') and 'evil.example' not in resp.headers['Location']
    resp = client.post(f'/like_post/{post_id}', headers={'Referer': 'http://localhost/posts'})
    assert resp.headers['Location'] == 'http://localhost/posts'


def test_register_rate_limited():
    reset()
    # A meaningful (non-loopback) IP: 10 per hour per visitor. On loopback
    # (onion service) the limit is a much higher shared ceiling (audit H1).
    client = app.test_client()
    client.environ_base['REMOTE_ADDR'] = '203.0.113.50'
    codes = []
    for i in range(12):
        resp = client.post('/register', data={
            'username': f'user{i}', 'password': PASSWORD + str(i),
            'confirm_password': PASSWORD + str(i)})
        codes.append(resp.status_code)
    with app.app_context():
        assert User.query.count() == 10


def test_purge_store():
    store = {f'k{i}': [1.0] for i in range(20)}
    store['fresh'] = [time.time()]
    utils.purge_store(store, max_keys=5)
    assert list(store) == ['fresh']


# ------------------------------------------------------------- Fix 3 : TOTP

def totp_user(name='twofa', legacy_plain=False):
    secret = pyotp.random_base32()
    uid = make_user(name)
    with app.app_context():
        user = User.query.get(uid)
        if legacy_plain:
            user.totp_secret = secret
        else:
            routes._store_totp_secret(user, secret)
        user.totp_enabled = True
        db.session.commit()
    return secret


def pass_step_one(name='twofa'):
    client, resp = sign_in(name)
    assert resp.status_code == 302 and '/login/totp' in resp.headers['Location']
    return client


def test_totp_secret_encrypted_at_rest_and_login_works():
    reset()
    secret = totp_user()
    with app.app_context():
        stored = User.query.filter_by(username='twofa').one().totp_secret
        assert stored != secret and secret not in stored
    client = pass_step_one()
    resp = client.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 302 and '/login' not in resp.headers['Location']
    assert authed_page(client)


def test_totp_legacy_plaintext_secret_still_works_and_is_encrypted():
    reset()
    secret = totp_user(legacy_plain=True)
    client = pass_step_one()
    resp = client.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 302
    assert authed_page(client)
    with app.app_context():
        stored = User.query.filter_by(username='twofa').one().totp_secret
        assert stored != secret
        assert message_encryption.decrypt_message(stored) == secret


def test_totp_code_cannot_be_replayed():
    reset()
    secret = totp_user()
    code = pyotp.TOTP(secret).now()
    first = pass_step_one()
    assert first.post('/login/totp', data={'code': code}).status_code == 302
    assert authed_page(first)
    second = pass_step_one()
    resp = second.post('/login/totp', data={'code': code})
    assert resp.status_code == 200          # refuse, formulaire reaffiche
    assert not authed_page(second)


def test_totp_attempt_limit_clears_pending_state():
    reset()
    secret = totp_user()
    client = pass_step_one()
    for _ in range(5):
        assert client.post('/login/totp', data={'code': '000000'}).status_code == 200
    resp = client.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 302 and resp.headers['Location'].endswith('/login')
    with client.session_transaction() as sess:
        assert 'pre_2fa_user_id' not in sess
    # un nouveau cookie ne contourne pas la limite : elle est cote serveur
    again = pass_step_one()
    resp = again.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 302 and resp.headers['Location'].endswith('/login')
    assert not authed_page(again)


def test_totp_pending_state_expires():
    reset()
    secret = totp_user()
    client = pass_step_one()
    with client.session_transaction() as sess:
        sess['pre_2fa_at'] = int(time.time()) - 301
    resp = client.post('/login/totp', data={'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 302 and resp.headers['Location'].endswith('/login')
    assert not authed_page(client)


def test_totp_setup_stores_encrypted_and_disable_needs_fresh_code():
    reset()
    make_user('reader')
    client = logged_in('reader')
    client.get('/totp/setup')
    with client.session_transaction() as sess:
        secret = sess['totp_pending_secret']
    resp = client.post('/totp/setup', data={'code': pyotp.TOTP(secret).now()})
    # the recovery codes are shown once, on the response itself (not a redirect)
    assert resp.status_code == 200 and 'recovery' in resp.get_data(as_text=True).lower()
    with app.app_context():
        user = User.query.filter_by(username='reader').one()
        assert user.totp_enabled and user.totp_secret != secret
        assert user.totp_last_counter is not None
    # la session en cours survit a l'activation
    assert authed_page(client)
    # le code deja consomme ne desactive pas la 2FA
    resp = client.post('/totp/disable', data={'password': PASSWORD,
                                              'code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 200
    with app.app_context():
        assert User.query.filter_by(username='reader').one().totp_enabled


def test_totp_issuer_is_brand_name():
    with app.test_request_context('/'):
        import qrcode  # noqa: F401
        uri = pyotp.totp.TOTP(pyotp.random_base32()).provisioning_uri(
            name='u', issuer_name='depressedyoungman')
    assert 'depressedyoungman' in uri
    assert 'MyBlog' not in open(routes.__file__, encoding='utf-8').read()


# ------------------------------------------------------------- Fix 4 : API mobile

def test_mobile_api_disabled_by_default_and_requires_admin_2fa():
    # Behaviour changed on purpose (audit M4): off unless MOBILE_API_ENABLED is
    # truthy, and an admin without 2FA is refused (403) even when enabled.
    reset()
    make_user('boss', admin=True)
    os.environ.pop('MOBILE_API_ENABLED', None)
    assert app.test_client().get('/api/admin/mobile/ping',
                                 headers=basic('boss', PASSWORD)).status_code == 404
    os.environ['MOBILE_API_ENABLED'] = 'true'
    client = app.test_client()
    assert client.get('/api/admin/mobile/ping').status_code == 401
    resp = client.get('/api/admin/mobile/ping', headers=basic('boss', PASSWORD))
    assert resp.status_code == 403 and 'Two-factor' in resp.get_json()['error']
    secret = pyotp.random_base32()
    with app.app_context():
        user = User.query.filter_by(username='boss').one()
        routes._store_totp_secret(user, secret)
        user.totp_enabled = True
        db.session.commit()
    resp = client.get('/api/admin/mobile/ping',
                      headers={**basic('boss', PASSWORD), 'X-TOTP-Code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 200 and resp.get_json()['admin']['username'] == 'boss'


def test_mobile_api_can_be_disabled():
    reset()
    make_user('boss', admin=True)
    os.environ['MOBILE_API_ENABLED'] = 'false'
    try:
        resp = app.test_client().get('/api/admin/mobile/ping', headers=basic('boss', PASSWORD))
        assert resp.status_code == 404
    finally:
        os.environ.pop('MOBILE_API_ENABLED', None)


def test_mobile_api_lockout_429():
    reset()
    make_user('boss', admin=True)
    client = app.test_client()
    for _ in range(10):
        assert client.get('/api/admin/mobile/ping',
                          headers=basic('boss', 'bad-password-xx')).status_code == 401
    resp = client.get('/api/admin/mobile/ping', headers=basic('boss', PASSWORD))
    assert resp.status_code == 429
    assert 'error' in resp.get_json()


def test_mobile_api_refuses_totp_banned_and_forced_change():
    reset()
    secret = pyotp.random_base32()
    uid = make_user('twofa', admin=True, totp_enabled=True)
    with app.app_context():
        user = User.query.get(uid)
        routes._store_totp_secret(user, secret)
        db.session.commit()
    make_user('banned', admin=True, is_banned=True)
    make_user('forced', admin=True, must_change_password=True)
    client = app.test_client()
    # Basic Auth alone cannot satisfy 2FA: the current code goes in X-TOTP-Code
    # (merged behaviour: 401 without a code, 200 with a valid one).
    resp = client.get('/api/admin/mobile/ping', headers=basic('twofa', PASSWORD))
    assert resp.status_code == 401 and 'two-factor' in resp.get_json()['error']
    resp = client.get('/api/admin/mobile/ping',
                      headers={**basic('twofa', PASSWORD),
                               'X-TOTP-Code': pyotp.TOTP(secret).now()})
    assert resp.status_code == 200
    for name in ('banned', 'forced'):
        resp = client.get('/api/admin/mobile/ping', headers=basic(name, PASSWORD))
        assert resp.status_code == 403, name
    # un mauvais mot de passe sur un compte 2FA reste un simple 401 (pas de fuite)
    resp = client.get('/api/admin/mobile/ping', headers=basic('twofa', 'bad-password-xx'))
    assert resp.status_code == 401


def test_mobile_api_constant_time_for_unknown_user():
    reset()
    make_user('boss', admin=True)
    client = app.test_client()

    def timed(name):
        start = time.perf_counter()
        client.get('/api/admin/mobile/ping', headers=basic(name, 'bad-password-xx'))
        return time.perf_counter() - start

    unknown = min(timed(f'nobody{i}') for i in range(2))
    known = min(timed('boss') for _ in range(2))
    assert unknown > 0.05, unknown        # bcrypt a bien ete execute
    assert abs(unknown - known) < max(known, unknown) * 0.7


# ------------------------------------------------------------- Fix 5 : images

def test_strip_metadata_jpeg_exif_gps(tmp_path=None):
    import piexif
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, 'a.jpg')
    exif = piexif.dump({'GPS': {piexif.GPSIFD.GPSLatitudeRef: b'N',
                                piexif.GPSIFD.GPSLatitude: ((48, 1), (51, 1), (0, 1))},
                        '0th': {piexif.ImageIFD.Make: b'Camera'}})
    Image.new('RGB', (32, 32), 'red').save(path, 'JPEG', exif=exif)
    assert len(Image.open(path).getexif()) > 0   # le fichier de depart en a bien
    routes.strip_image_metadata(path)
    with Image.open(path) as out:
        assert len(out.getexif()) == 0
        for key in ('exif', 'icc_profile', 'xmp'):
            assert key not in out.info


def test_strip_metadata_png_text_chunk_and_gif_palette():
    tmp = tempfile.mkdtemp()
    png = os.path.join(tmp, 'a.png')
    meta = PngInfo()
    meta.add_text('Author', 'secret person')
    Image.new('RGB', (16, 16), 'blue').save(png, 'PNG', pnginfo=meta)
    assert 'Author' in Image.open(png).text
    routes.strip_image_metadata(png)
    with Image.open(png) as out:
        assert 'Author' not in (getattr(out, 'text', {}) or {})
        assert 'Author' not in out.info

    gif = os.path.join(tmp, 'a.gif')
    pal = Image.new('P', (8, 8))
    pal.putpalette([255, 0, 0, 0, 255, 0, 0, 0, 255] + [0] * (256 * 3 - 9))
    pal.putpixel((0, 0), 2)
    pal.save(gif, 'GIF')
    before = Image.open(gif)
    before_palette, before_px = before.getpalette()[:9], before.getpixel((0, 0))
    routes.strip_image_metadata(gif)
    with Image.open(gif) as out:
        assert out.getpalette()[:9] == before_palette
        assert out.getpixel((0, 0)) == before_px


def test_strip_metadata_memory_is_bounded():
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, 'big.png')
    Image.new('RGB', (2000, 2000), 'white').save(path, 'PNG')
    tracemalloc.start()
    try:
        routes.strip_image_metadata(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024 * 1024, peak
    assert routes.get_file_type('x.webp') == 'image'
    assert Image.MAX_IMAGE_PIXELS == routes.MAX_IMAGE_PIXELS


# ------------------------------------------------------------- Fix 6 : sessions

def test_password_change_invalidates_other_sessions_and_remember_cookie():
    reset()
    make_user('alice')
    a = logged_in('alice')
    b, resp = sign_in('alice')
    assert resp.status_code == 302
    # B garde aussi un cookie "remember"
    b2 = app.test_client()
    resp = b2.post('/login', data={'username': 'alice', 'password': PASSWORD,
                                   'remember_me': 'y'})
    assert resp.status_code == 302
    assert authed_page(b) and authed_page(b2)

    resp = a.post('/account/password', data={
        'current_password': PASSWORD, 'new_password': PASSWORD + '-new',
        'confirm_password': PASSWORD + '-new'})
    assert resp.status_code == 302
    assert authed_page(a)              # la session qui a change le mot de passe reste valide
    assert not authed_page(b)
    # cookie de session supprime, il ne reste que le "remember"
    b2.delete_cookie('sid')
    assert not authed_page(b2)


def test_legacy_cookie_without_token_stays_valid_until_rotation():
    reset()
    uid = make_user('old')
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(uid)       # ancien format : id seul
        sess['_fresh'] = True
    assert authed_page(client)
    with app.app_context():
        User.query.get(uid).rotate_session_token()
        db.session.commit()
    assert not authed_page(client)


# ------------------------------------------------------------- Fix 7 : brouillons

def test_unpublished_posts_hidden_from_public():
    reset()
    admin = make_user('admin', admin=True)
    future = make_post(admin, published=False,
                       scheduled=utils.datetime.utcnow() + timedelta(days=7),
                       title='FutureSecret')
    draft = make_post(admin, published=False, draft=True, title='DraftSecret')
    live = make_post(admin, published=True, title='LiveOne')
    anon = app.test_client()
    for url in ('/', '/posts'):
        html = anon.get(url).get_data(as_text=True)
        assert 'LiveOne' in html
        assert 'DraftSecret' not in html and 'FutureSecret' not in html
    assert anon.get(f'/post/{draft}').status_code == 404
    assert anon.get(f'/post/{future}').status_code == 404
    assert anon.get(f'/post/{live}').status_code == 200
    assert anon.post(f'/like_post/{draft}').status_code in (302, 401, 404)
    boss = logged_in('admin')
    assert boss.get(f'/post/{draft}').status_code == 200


def test_posting_without_date_stays_draft_and_future_date_is_scheduled():
    reset()
    make_user('admin', admin=True)
    boss = logged_in('admin')
    boss.post('/manage_posts', data={'title': 'D1', 'content': 'c'})
    boss.post('/manage_posts', data={'title': 'S1', 'content': 'c',
                                     'scheduled_date': '2999-01-01 00:00:00'})
    boss.post('/manage_posts', data={'title': 'P1', 'content': 'c', 'is_published': 'y'})
    with app.app_context():
        d, s, p = (Post.query.filter_by(title=t).one() for t in ('D1', 'S1', 'P1'))
        assert (d.is_published, d.is_draft, d.scheduled_date) == (False, True, None)
        assert (s.is_published, s.is_draft) == (False, False) and s.scheduled_date
        assert (p.is_published, p.is_draft) == (True, False)
    # requetes suivantes : le brouillon n'est jamais publie automatiquement
    anon = app.test_client()
    anon.get('/')
    anon.get('/')
    with app.app_context():
        assert Post.query.filter_by(title='D1').one().is_published is False
        assert Post.query.filter_by(title='S1').one().is_published is False


def test_due_scheduled_post_published_on_next_request():
    reset()
    admin = make_user('admin', admin=True)
    past = utils.datetime(2020, 1, 1)
    post_id = make_post(admin, published=False, scheduled=past, title='Due')
    anon = app.test_client()
    html = anon.get('/').get_data(as_text=True)
    assert 'Due' in html
    with app.app_context():
        post = Post.query.get(post_id)
        assert post.is_published and post.is_draft is False


# ------------------------------------------------------------- Fix 8 : Socket.IO supprime
# (le serveur ne l'expose plus : voir test_audit_fixes.py)


# ------------------------------------------------------------- Fix 9 : suppressions

def test_delete_post_with_comments_likes_notifications():
    reset()
    admin = make_user('admin', admin=True)
    reader = make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        c = Comment(content='x', post_id=post_id, author_id=reader)
        db.session.add(c)
        db.session.flush()
        child = Comment(content='y', post_id=post_id, author_id=admin, parent_id=c.id)
        db.session.add_all([child, Like(user_id=reader, post_id=post_id),
                            Like(user_id=admin, comment_id=c.id),
                            Revision(post_id=post_id, content='r', version=1),
                            Notification(user_id=admin, type='comment', title='t',
                                         message='m', related_post_id=post_id,
                                         related_comment_id=c.id)])
        db.session.commit()
    boss = logged_in('admin')
    resp = boss.post(f'/delete_post/{post_id}')
    assert resp.status_code == 302
    with app.app_context():
        assert Post.query.count() == 0 and Comment.query.count() == 0
        assert Like.query.count() == 0 and Revision.query.count() == 0
        assert Notification.query.count() == 1
        note = Notification.query.one()
        assert note.related_post_id is None and note.related_comment_id is None


def test_delete_user_with_messages_likes_comments():
    reset()
    admin = make_user('admin', admin=True)
    reader = make_user('reader')
    post_id = make_post(admin)
    tmp = tempfile.mkdtemp()
    old_folder = routes.UPLOAD_FOLDER
    routes.UPLOAD_FOLDER = tmp
    try:
        attachment = os.path.join(tmp, 'f.txt')
        open(attachment, 'w').write('x')
        with app.app_context():
            msg = Message(sender_id=reader, receiver_id=admin, file_path='f.txt')
            msg.set_encrypted_content('hi')
            c = Comment(content='mine', post_id=post_id, author_id=reader)
            db.session.add_all([msg, c, Like(user_id=reader, post_id=post_id),
                                Notification(user_id=reader, type='like', title='t',
                                             message='m')])
            Post.query.get(post_id).likes_count = 1
            db.session.commit()
        boss = logged_in('admin')

        # sans confirmation explicite : rien n'est supprime
        boss.post(f'/delete_user/{reader}')
        with app.app_context():
            assert User.query.filter_by(username='reader').count() == 1
            assert Message.query.count() == 1
        assert os.path.exists(attachment)

        resp = boss.post(f'/delete_user/{reader}', data={'purge_messages': '1'})
        assert resp.status_code == 302
        with app.app_context():
            assert User.query.filter_by(username='reader').count() == 0
            assert Message.query.count() == 0 and Like.query.count() == 0
            assert Comment.query.one().author_id is None
            assert Post.query.get(post_id).likes_count == 0
        assert not os.path.exists(attachment)
        assert '[deleted]' in app.test_client().get(f'/post/{post_id}').get_data(as_text=True)
    finally:
        routes.UPLOAD_FOLDER = old_folder


def test_delete_user_refuses_self_and_admin():
    reset()
    admin = make_user('admin', admin=True)
    other = make_user('other', admin=True)
    boss = logged_in('admin')
    boss.post(f'/delete_user/{admin}')
    boss.post(f'/delete_user/{other}')
    with app.app_context():
        assert User.query.count() == 2


# ------------------------------------------------------------- Fix 10 : /donate

def test_donate_rejects_bad_amounts():
    reset()
    make_user('admin', admin=True)
    client = logged_in('admin')   # only an admin may record an amount
    for bad in ('abc', 'inf', 'nan', '-1', '0', '1e9', ''):
        resp = client.post('/donate', data={'amount': bad})
        assert resp.status_code == 302, bad
    with app.app_context():
        assert Donor.query.count() == 0
    assert client.post('/donate', data={'amount': '5.123456'}).status_code == 302
    with app.app_context():
        assert Donor.query.one().amount == 5.1235


def test_donate_rate_limited():
    reset()
    make_user('admin', admin=True)
    client = logged_in('admin')
    for _ in range(5):
        client.post('/donate', data={'amount': '1'})
    with app.app_context():
        assert Donor.query.count() == 3


# ------------------------------------------------------------- Fix 11 : likes

def test_like_unlike_cycles_do_not_farm_xp_or_notifications():
    reset()
    admin = make_user('admin', admin=True)
    make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        c = Comment(content='c', content_format='bbcode', post_id=post_id, author_id=admin)
        db.session.add(c)
        db.session.commit()
        comment_id = c.id
        xp = User.query.get(admin).experience_points or 0
    client = logged_in('reader')
    for _ in range(10):
        client.post(f'/like_post/{post_id}')
    with app.app_context():
        user = User.query.get(admin)
        assert (user.experience_points or 0) == xp
        assert Notification.query.filter_by(user_id=admin, type='like').count() == 0
    for _ in range(10):
        client.post(f'/like_comment/{comment_id}')
    with app.app_context():
        assert (User.query.get(admin).experience_points or 0) == xp
        assert Notification.query.filter_by(user_id=admin, type='like').count() == 0
        assert Like.query.count() == 0
    # un like laisse bien l'XP et une notification
    client.post(f'/like_post/{post_id}')
    with app.app_context():
        assert (User.query.get(admin).experience_points or 0) == xp + 5
        assert Notification.query.filter_by(user_id=admin, type='like').count() == 1


def test_like_comment_rate_limited():
    reset()
    admin = make_user('admin', admin=True)
    make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        c = Comment(content='c', content_format='bbcode', post_id=post_id, author_id=admin)
        db.session.add(c)
        db.session.commit()
        cid = c.id
    client = logged_in('reader')
    for _ in range(21):
        client.post(f'/like_comment/{cid}')
    with app.app_context():
        assert Like.query.count() == 0   # 20 bascules (paires) + la 21e refusee -> impair bloque
        assert Comment.query.get(cid).likes_count == 0


if __name__ == '__main__':
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            try:
                fn()
                print('ok   ', name)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print('FAIL ', name, repr(exc))
    sys.exit(1 if failed else 0)
