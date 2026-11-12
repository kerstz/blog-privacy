"""Regression tests of the 2026-11-12 audit (production readiness pass)."""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_security_fixes import app, make_post, make_user, reset  # noqa: E402
from app import db, utils  # noqa: E402
from app.models import Comment  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------- BBCode: no attribute breakout

BREAKOUT_PAYLOADS = [
    # a tag written inside a URL used to be expanded inside the href attribute
    '[url]http://a.example/[img]http://b.example/x/style=position:fixed;top:0;left:0;'
    'width:100vw;height:100vh;opacity:0;[/img][/url]',
    '[img]http://x.example/[color=red]a[/color][/img]',
    '[url=http://a.example/[b]x[/url]',
    '[img=10,10]http://x.example/[size=12]a[/size][/img]',
    '[url]http://a.example/[url]http://b.example/[/url][/url]',
]


def _attribute_values(html):
    return re.findall(r'\s(?:href|src|style)="([^"]*)"', html)


def test_bbcode_tags_inside_urls_never_reach_an_attribute():
    for payload in BREAKOUT_PAYLOADS:
        raw = utils.parse_bbcode(payload)
        for value in _attribute_values(raw):
            assert '<' not in value and '>' not in value, (payload, raw)
        # an attribute never ends inside a generated tag: every quote is paired
        for tag in re.findall(r'<[a-z][^>]*>', raw):
            assert tag.count('"') % 2 == 0, (payload, tag)
        assert '[' not in ''.join(_attribute_values(raw)), (payload, raw)


def test_comment_cannot_inject_style_on_a_link():
    reset()
    admin = make_user('boss', admin=True)
    post_id = make_post(admin)
    with app.app_context():
        for payload in BREAKOUT_PAYLOADS:
            db.session.add(Comment(content=payload, content_format='bbcode',
                                   post_id=post_id, author_id=admin))
        db.session.commit()
    html = app.test_client().get(f'/post/{post_id}').get_data(as_text=True)
    section = html.split('comments-section', 1)[1]
    assert not re.search(r'<a[^>]*\sstyle=', section)
    assert 'style="color:red"><' not in section


def test_comment_output_goes_through_the_allow_list():
    """Defence in depth: the BBCode output is filtered by nh3 at render time."""
    out = str(app.jinja_env.filters['comment_html']('[b]bold[/b] [url=http://e.example]l[/url]'))
    assert '<strong>bold</strong>' in out
    assert 'rel="nofollow noopener noreferrer"' in out
    out = str(app.jinja_env.filters['bbcode']('[b]t[/b] <b onclick=x>t</b>'))
    assert '<strong>t</strong>' in out
    assert not re.search(r'<[^>]*onclick', out)


def test_bbcode_formatting_still_rendered():
    out = utils.render_user_bbcode(
        '[b]b[/b] [i]i[/i] [u]u[/u] [s]s[/s] [quote]q[/quote] [code]c[/code] '
        '[color=red]r[/color] [size=20]z[/size] [center]m[/center] '
        '[list][*]one[/list] [list=1][*]two[/list] [img]/uploads/a.webp[/img] '
        '[url=https://example.org/?a=1&b=[2]]x[/url]')
    for fragment in ('<strong>b</strong>', '<em>i</em>', '<u>u</u>', '<s>s</s>',
                     '<blockquote>q</blockquote>', '<pre><code>c</code></pre>',
                     'style="color:red"', 'font-size:20px', 'text-align:center',
                     '<ul><li>one</li></ul>', '<ol><li>two</li></ol>',
                     '<img src="/uploads/a.webp"'):
        assert fragment in out, fragment
    assert 'https://example.org/?a=1&amp;b=%5B2' in out


def test_bbcode_url_tags_do_not_backtrack_for_seconds():
    """A line of unclosed [url=...] tags used to cost ~3 s of CPU per render."""
    started = time.perf_counter()
    utils.parse_bbcode('[url=a]' * 700)
    utils.parse_bbcode(('[url=http://a]' + '[b]' * 3) * 200)
    assert time.perf_counter() - started < 0.5


# ------------------------------------------- Tor behind a trusted proxy

class _BehindProxy:
    """Run the app behind ProxyFix, as with TRUSTED_PROXY_COUNT=1 in production
    (Caddy/nginx in front, Tor routed through the proxy: deploy/torrc.example)."""

    def __enter__(self):
        from werkzeug.middleware.proxy_fix import ProxyFix
        self.orig = app.wsgi_app
        app.wsgi_app = ProxyFix(self.orig, x_for=1, x_proto=1, x_host=1)
        app.config['TRUSTED_PROXY_COUNT'] = 1
        return self

    def __exit__(self, *exc):
        app.wsgi_app = self.orig
        app.config['TRUSTED_PROXY_COUNT'] = 0


TOR = {'X-Forwarded-For': '127.0.0.1'}


def test_tor_visitor_behind_trusted_proxy_cannot_lock_everyone_out():
    from test_security_fixes import PASSWORD
    reset()
    make_user('alice')
    make_user('boss', admin=True)
    with _BehindProxy():
        attacker = app.test_client()
        for i in range(8):
            attacker.post('/login', headers=TOR,
                          data={'username': f'ghost{i}', 'password': 'wrong-password-1'})
        for name in ('alice', 'boss'):
            resp = app.test_client().post('/login', headers=TOR,
                                          data={'username': name, 'password': PASSWORD})
            assert resp.status_code == 302, name


def test_clearnet_client_behind_trusted_proxy_keeps_its_own_lock():
    from test_security_fixes import PASSWORD
    reset()
    make_user('alice')
    with _BehindProxy():
        attacker = app.test_client()
        bad = {'X-Forwarded-For': '203.0.113.7'}
        for i in range(5):
            attacker.post('/login', headers=bad,
                          data={'username': f'ghost{i}', 'password': 'wrong-password-1'})
        resp = attacker.post('/login', headers=bad, data={'username': 'alice', 'password': PASSWORD})
        assert resp.status_code == 200  # this client is locked...
        resp = app.test_client().post('/login', headers={'X-Forwarded-For': '203.0.113.8'},
                                      data={'username': 'alice', 'password': PASSWORD})
        assert resp.status_code == 302  # ...nobody else is


def test_shared_anonymous_limits_are_a_ceiling_not_per_visitor():
    """Search (30/min per visitor) must not be exhausted for every onion
    visitor by one of them: anonymous loopback clients share a higher ceiling."""
    reset()
    onion = app.test_client()
    codes = {onion.get('/search?q=hello').status_code for _ in range(40)}
    assert codes == {200}
    clearnet = app.test_client()
    clearnet.environ_base['REMOTE_ADDR'] = '203.0.113.9'
    codes = [clearnet.get('/search?q=hello').status_code for _ in range(31)]
    assert codes[-1] == 429


# ------------------------------------------- 2FA: daily cap on wrong codes

def _wrong_codes(user_id, count, valid):
    """Type `count` wrong codes through verify_second_factor (the shared path of
    login, re-authentication and 2FA disable), skipping the valid ones."""
    from app import services
    from app.models import User
    wrong = [f'{n:06d}' for n in range(1000) if f'{n:06d}' not in valid][:count]
    with app.app_context():
        user = db.session.get(User, user_id)
        for code in wrong:
            assert not services.verify_second_factor(user, code)


def test_second_factor_daily_cap_blocks_login_until_unlock():
    import pyotp
    from test_security_fixes import pass_step_one, totp_user
    from app import services
    reset()
    secret = totp_user('twofa')
    totp = pyotp.TOTP(secret)
    with app.app_context():
        from app.models import User
        uid = User.query.filter_by(username='twofa').one().id
    valid = {totp.at(time.time() + d) for d in (-60, -30, 0, 30, 60)}
    _wrong_codes(uid, services.SECOND_FACTOR_DAILY_FAILURES, valid)
    client = pass_step_one('twofa')
    resp = client.post('/login/totp', data={'code': totp.now()})
    assert resp.status_code == 302 and '/login/totp' not in resp.headers['Location']
    assert not client.get('/account/security').status_code == 200
    # the operator clears it
    result = app.test_cli_runner().invoke(args=['unlock', 'twofa'])
    assert result.exit_code == 0
    client = pass_step_one('twofa')
    resp = client.post('/login/totp', data={'code': totp.now()})
    assert resp.status_code == 302
    assert client.get('/account/security').status_code == 200


def test_recovery_code_not_consumed_while_locked():
    from test_security_fixes import totp_user
    from app import services
    from app.models import User
    reset()
    totp_user('twofa')
    with app.app_context():
        user = User.query.filter_by(username='twofa').one()
        codes = services.generate_recovery_codes(user)
        db.session.commit()
        uid = user.id
    _wrong_codes(uid, services.SECOND_FACTOR_DAILY_FAILURES, set())
    with app.app_context():
        user = db.session.get(User, uid)
        assert not services.verify_second_factor(user, codes[0])
        assert services.recovery_codes_left(user) == len(codes)


def test_mobile_api_wrong_codes_count_towards_daily_cap():
    from test_security_fixes import PASSWORD, basic
    from test_audit_fixes import _totp_admin
    from app import services
    reset()
    totp = _totp_admin('boss')
    client = app.test_client()
    headers = basic('boss', PASSWORD)
    valid = {totp.at(time.time() + d) for d in (-60, -30, 0, 30, 60)}
    wrong = [f'{n:06d}' for n in range(100) if f'{n:06d}' not in valid]
    for i in range(services.SECOND_FACTOR_DAILY_FAILURES):
        utils.clear_failures('admin_api:user:' + utils.hashed_key('boss'))  # past the 15-min lock
        resp = client.get('/api/admin/mobile/ping', headers={**headers, 'X-TOTP-Code': wrong[i]})
        assert resp.status_code == 401
    utils.clear_failures('admin_api:user:' + utils.hashed_key('boss'))
    resp = client.get('/api/admin/mobile/ping', headers={**headers, 'X-TOTP-Code': totp.now()})
    assert resp.status_code == 401


# ------------------------------------------- uploads: no plaintext on disk

def _jpeg_with_gps(size=(4000, 3000)):
    import io
    from PIL import Image
    img = Image.new('RGB', size, (120, 30, 200))
    exif = Image.Exif()
    exif[0x010F] = 'SpyCam'          # Make
    exif[0x8825] = {2: (48, 51, 0)}  # GPS latitude
    buf = io.BytesIO()
    img.save(buf, 'JPEG', exif=exif, quality=80)
    buf.seek(0)
    return buf


class _NoSave:
    """FileStorage stand-in whose save() must never be called."""

    def __init__(self, stream, filename):
        self.stream, self.filename = stream, filename

    def save(self, *a, **k):  # pragma: no cover - the assertion is the test
        raise AssertionError('the plaintext upload was written to disk')


def test_upload_pipeline_never_writes_plaintext(tmp_path, monkeypatch):
    import io
    from PIL import Image
    from app import services
    monkeypatch.setenv('UPLOAD_DIR', str(tmp_path / 'up'))
    reset()
    uid = make_user('alice')
    with app.test_request_context():
        from app.models import User
        user = db.session.get(User, uid)
        path, kind = services._store_upload(_NoSave(_jpeg_with_gps(), 'trip.jpg'), 'chat', user=user)
        doc, doc_kind = services._store_upload(_NoSave(io.BytesIO(b'%PDF-1.4 secret'), 'a.pdf'),
                                               'chat', user=user)
    files = sorted(p.name for p in (tmp_path / 'up').iterdir())
    assert all(name.endswith('.enc') for name in files) and len(files) == 2
    assert kind == 'image' and path.endswith('.webp.enc') and doc.endswith('.pdf.enc')
    for name in files:
        assert ((tmp_path / 'up' / name).stat().st_mode & 0o777) == 0o600
        raw = (tmp_path / 'up' / name).read_bytes()
        assert b'SpyCam' not in raw and b'secret' not in raw and b'WEBP' not in raw[:64]
    with Image.open(io.BytesIO(services.read_upload_bytes(path))) as img:
        assert img.format == 'WEBP' and max(img.size) <= 1600
        assert not img.info.get('exif') and not img.getexif()
    assert services.read_upload_bytes(doc) == b'%PDF-1.4 secret'


def test_blocked_image_is_quarantined_from_memory(tmp_path, monkeypatch):
    import pytest
    from app import services
    from app.image_safety import dhash_of_bytes, format_dhash, sha256_of_bytes
    from app.models import BlockedImageHash, User
    monkeypatch.setenv('UPLOAD_DIR', str(tmp_path / 'up'))
    monkeypatch.setenv('QUARANTINE_DIR', str(tmp_path / 'q'))
    reset()
    uid = make_user('mallory')
    data = _jpeg_with_gps((64, 48)).getvalue()
    with app.test_request_context():
        db.session.add(BlockedImageHash(sha256=sha256_of_bytes(data),
                                        dhash=format_dhash(dhash_of_bytes(data)), label='t'))
        db.session.commit()
        user = db.session.get(User, uid)
        import io
        with pytest.raises(services.UploadRefused):
            services._store_upload(_NoSave(io.BytesIO(data), 'x.jpg'), 'chat', user=user)
        assert db.session.get(User, uid).is_banned
    quarantined = [p for p in (tmp_path / 'q').iterdir() if not p.name.endswith('.txt')]
    assert len(quarantined) == 1 and quarantined[0].read_bytes() == data
    assert (quarantined[0].stat().st_mode & 0o777) == 0o600
    assert not (tmp_path / 'up').exists() or not any((tmp_path / 'up').iterdir())


# ------------------------------------------- public pages: no time of day

def _post_with_comment(when):
    from app.models import Post
    admin = make_user('boss', admin=True)
    reader = make_user('reader')
    with app.app_context():
        post = Post(title='T', content='c', author_id=admin, is_published=True,
                    is_draft=False, date_posted=when)
        db.session.add(post)
        db.session.commit()
        db.session.add(Comment(content='hi', content_format='bbcode', post_id=post.id,
                               author_id=reader, date_posted=when))
        db.session.commit()
        return post.id


def test_public_dates_hide_the_time_of_day(monkeypatch):
    from datetime import datetime
    monkeypatch.delenv('PUBLIC_TIME_PRECISION', raising=False)
    reset()
    post_id = _post_with_comment(datetime(2026, 8, 24, 3, 47, 12))
    client = app.test_client()
    for page in (f'/post/{post_id}', '/', '/posts'):
        html = client.get(page).get_data(as_text=True)
        assert '03:47' not in html, page
        assert 'August 24, 2026' in html, page
    feed = client.get('/feed.xml').get_data(as_text=True)
    assert '<pubDate>Mon, 24 Aug 2026 00:00:00 +0000</pubDate>' in feed
    assert '<title>depressedyoungmanblog</title>' in feed
    # the operator can opt back in
    monkeypatch.setenv('PUBLIC_TIME_PRECISION', 'minute')
    assert '03:47' in client.get(f'/post/{post_id}').get_data(as_text=True)
    assert '03:47:12 +0000' in client.get('/feed.xml').get_data(as_text=True)


def test_profile_picture_only_rendered_for_who_can_load_it():
    from app.models import User
    from test_security_fixes import logged_in
    reset()
    owner = make_user('alice')
    make_user('bob')
    with app.app_context():
        db.session.get(User, owner).profile_picture = 'uploads/profile_x.webp.enc'
        db.session.commit()
    assert 'profile_x.webp.enc' not in app.test_client().get(f'/profile/{owner}').get_data(as_text=True)
    assert 'profile_x.webp.enc' not in logged_in('bob').get(f'/profile/{owner}').get_data(as_text=True)
    assert 'profile_x.webp.enc' in logged_in('alice').get(f'/profile/{owner}').get_data(as_text=True)


def test_pending_totp_secret_is_not_readable_in_the_session_cookie():
    from test_security_fixes import logged_in
    reset()
    make_user('alice')
    client = logged_in('alice')
    html = client.get('/totp/setup').get_data(as_text=True)
    secret = re.search(r'\b([A-Z2-7]{32})\b', html).group(1)
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'])
    payload = app.session_interface.get_signing_serializer(app).loads(cookie.value)
    assert secret not in repr(payload)
    assert secret not in cookie.value


# ------------------------------------------- headers and small rules

def test_hsts_never_sent_to_onion_or_loopback(monkeypatch):
    monkeypatch.delenv('FORCE_HSTS', raising=False)
    old = app.config['SESSION_COOKIE_SECURE']
    app.config['SESSION_COOKIE_SECURE'] = True
    try:
        client = app.test_client()
        onion = 'a' * 56 + '.onion'
        for host in (onion, '127.0.0.1:8877', 'localhost', '[::1]:8000'):
            resp = client.get('/healthz', headers={'Host': host})
            assert 'Strict-Transport-Security' not in resp.headers, host
        assert 'Strict-Transport-Security' in client.get('/healthz', headers={'Host': 'blog.example.org'}).headers
        assert 'Strict-Transport-Security' in client.get('/healthz', base_url='https://x' + onion[1:]).headers
        monkeypatch.setenv('FORCE_HSTS', 'true')
        assert 'Strict-Transport-Security' in client.get('/healthz', headers={'Host': onion}).headers
    finally:
        app.config['SESSION_COOKIE_SECURE'] = old


def test_permissions_policy_denies_topics():
    assert 'browsing-topics=()' in app.test_client().get('/').headers['Permissions-Policy']


def test_comment_on_unpublished_post_cannot_be_edited_by_its_author():
    from app.models import Post
    from test_security_fixes import logged_in
    reset()
    admin = make_user('boss', admin=True)
    reader = make_user('reader')
    post_id = make_post(admin)
    with app.app_context():
        comment = Comment(content='mine', content_format='bbcode', post_id=post_id, author_id=reader)
        db.session.add(comment)
        post = db.session.get(Post, post_id)
        post.is_published, post.is_draft = False, True
        db.session.commit()
        cid = comment.id
    client = logged_in('reader')
    assert client.get(f'/edit_comment/{cid}/{post_id}').status_code == 404
    assert client.post(f'/edit_comment/{cid}/{post_id}', data={'content': 'changed'}).status_code == 404
    with app.app_context():
        assert db.session.get(Comment, cid).content == 'mine'


# ------------------------------------------- encryption key rotation

def test_rotate_key_reencrypts_messages_totp_and_files(tmp_path, monkeypatch):
    import base64
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from app import services
    from app.encryption import message_encryption
    from app.models import Message, User

    def fernet(key, salt, iterations):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=iterations)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(key.encode())))

    monkeypatch.setenv('UPLOAD_DIR', str(tmp_path / 'up'))
    (tmp_path / 'up').mkdir()
    old_key, old_salt = os.environ['ENCRYPTION_KEY'], os.environ['ENCRYPTION_SALT']
    old_iter = int(os.environ.get('ENCRYPTION_ITERATIONS') or 100000)
    reset()
    alice, boss = make_user('alice'), make_user('boss', admin=True)
    with app.app_context():
        msg = Message(sender_id=alice, receiver_id=boss, file_path='uploads/chat_k.pdf.enc')
        msg.set_encrypted_content('private words')
        db.session.add(msg)
        user = db.session.get(User, alice)
        services._store_totp_secret(user, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
        user.totp_enabled = True
        db.session.commit()
    services.write_encrypted_file(str(tmp_path / 'up' / 'chat_k.pdf.enc'), b'attachment')
    assert app.test_cli_runner().invoke(args=['rotate-key']).exit_code != 0  # no old key set

    try:
        # new key + more iterations; the previous values become ENCRYPTION_OLD_*
        monkeypatch.setenv('ENCRYPTION_OLD_KEY', old_key)
        monkeypatch.setenv('ENCRYPTION_OLD_SALT', old_salt)
        monkeypatch.setenv('ENCRYPTION_OLD_ITERATIONS', str(old_iter))
        monkeypatch.setenv('ENCRYPTION_KEY', 'n' * 40)
        monkeypatch.setenv('ENCRYPTION_SALT', 'm' * 20)
        monkeypatch.setenv('ENCRYPTION_ITERATIONS', '600000')
        message_encryption.configure()
        with app.app_context():
            assert Message.query.one().get_decrypted_content() == 'private words'  # still readable
        dry = app.test_cli_runner().invoke(args=['rotate-key', '--dry-run'])
        assert dry.exit_code == 0 and 'Would re-encrypt 1 message(s), 1 2FA secret(s) and 1 file(s)' in dry.output
        result = app.test_cli_runner().invoke(args=['rotate-key'])
        assert result.exit_code == 0, result.output
        assert 'Re-encrypted 1 message(s), 1 2FA secret(s) and 1 file(s)' in result.output

        # the old key alone reads nothing any more, the new one alone reads everything
        for var in ('ENCRYPTION_OLD_KEY', 'ENCRYPTION_OLD_SALT', 'ENCRYPTION_OLD_ITERATIONS'):
            monkeypatch.delenv(var)
        message_encryption.configure()
        previous = fernet(old_key, old_salt, old_iter)
        with app.app_context():
            msg = Message.query.one()
            assert msg.get_decrypted_content() == 'private words'
            try:
                previous.decrypt(base64.urlsafe_b64decode(msg.content.encode()))
                raise AssertionError('message still readable with the old key')
            except InvalidToken:
                pass
            assert services._totp_secret(db.session.get(User, alice)) == 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        assert services.read_upload_bytes('uploads/chat_k.pdf.enc') == b'attachment'
        token = (tmp_path / 'up' / 'chat_k.pdf.enc').read_bytes()
        try:
            previous.decrypt(token)
            raise AssertionError('file still readable with the old key')
        except InvalidToken:
            pass
        assert ((tmp_path / 'up' / 'chat_k.pdf.enc').stat().st_mode & 0o777) == 0o600
    finally:
        monkeypatch.undo()
        message_encryption.configure()


def test_rotate_key_fails_loudly_on_unreadable_file(tmp_path, monkeypatch):
    from app.encryption import message_encryption
    monkeypatch.setenv('UPLOAD_DIR', str(tmp_path / 'up'))
    (tmp_path / 'up').mkdir()
    (tmp_path / 'up' / 'chat_bad.pdf.enc').write_bytes(b'not a fernet token')
    reset()
    try:
        monkeypatch.setenv('ENCRYPTION_OLD_KEY', 'o' * 40)
        message_encryption.configure()
        result = app.test_cli_runner().invoke(args=['rotate-key'])
        assert result.exit_code == 1
        assert 'chat_bad.pdf.enc' in result.output
    finally:
        monkeypatch.undo()
        message_encryption.configure()


# ------------------------------------------- migrations

def test_migrations_build_the_model_schema_on_a_blank_database(tmp_path):
    """`flask db upgrade` on an empty file must give exactly the schema of the
    models (`flask db check`), and the chain must go down and up again."""
    import subprocess
    env = dict(os.environ, DATABASE_URL=f'sqlite:///{tmp_path}/fresh.db', FLASK_APP='wsgi.py',
               SECURITY_STATE_DB=str(tmp_path / 's.db'), PYTHONWARNINGS='ignore')
    out = ''
    for args in (['db', 'upgrade'], ['db', 'check'], ['db', 'downgrade', 'base'],
                 ['db', 'upgrade'], ['db', 'check']):
        res = subprocess.run([sys.executable, '-m', 'flask', *args], cwd=REPO, env=env,
                             capture_output=True, text=True, timeout=300)
        assert res.returncode == 0, (args, res.stdout + res.stderr)
        out = res.stdout + res.stderr
    assert 'No new upgrade operations detected' in out


# ------------------------------------------- feature: retention purges

def test_purge_messages_deletes_old_rows_and_their_files(tmp_path, monkeypatch):
    from datetime import datetime, timedelta
    from app import services
    from app.models import Message, User
    monkeypatch.setenv('UPLOAD_DIR', str(tmp_path / 'up'))
    (tmp_path / 'up').mkdir()
    reset()
    alice, boss = make_user('alice'), make_user('boss', admin=True)
    old = datetime.utcnow() - timedelta(days=200)
    with app.app_context():
        for name, when in (('old.pdf.enc', old), ('shared.pdf.enc', old), ('shared.pdf.enc', datetime.utcnow()),
                           ('avatar.webp.enc', old), (None, old), (None, datetime.utcnow())):
            msg = Message(sender_id=alice, receiver_id=boss, timestamp=when,
                          file_path=f'uploads/{name}' if name else None)
            msg.set_encrypted_content('x')
            db.session.add(msg)
        db.session.get(User, alice).profile_picture = 'uploads/avatar.webp.enc'
        db.session.commit()
    for name in ('old.pdf.enc', 'shared.pdf.enc', 'avatar.webp.enc'):
        services.write_encrypted_file(str(tmp_path / 'up' / name), b'data')
    runner = app.test_cli_runner()
    assert runner.invoke(args=['purge-messages']).exit_code != 0          # no default period
    dry = runner.invoke(args=['purge-messages', '--days', '180', '--dry-run'])
    assert 'Would delete 4 message(s) and 1 attachment(s)' in dry.output
    with app.app_context():
        assert Message.query.count() == 6
    res = runner.invoke(args=['purge-messages', '--days', '180'])
    assert res.exit_code == 0 and 'Deleted 4 message(s) and 1 attachment(s)' in res.output
    with app.app_context():
        assert Message.query.count() == 2
    assert not (tmp_path / 'up' / 'old.pdf.enc').exists()
    assert (tmp_path / 'up' / 'shared.pdf.enc').exists()   # still used by a recent message
    assert (tmp_path / 'up' / 'avatar.webp.enc').exists()  # still a profile picture


def test_purge_notifications_keeps_recent_ones():
    from datetime import datetime, timedelta
    from app.models import Notification
    reset()
    uid = make_user('alice')
    with app.app_context():
        db.session.add(Notification(user_id=uid, type='like', title='t', message='m',
                                    created_at=datetime.utcnow() - timedelta(days=100)))
        db.session.add(Notification(user_id=uid, type='like', title='t', message='m'))
        db.session.commit()
    res = app.test_cli_runner().invoke(args=['purge-notifications'])
    assert res.exit_code == 0 and 'Deleted 1 notification(s) older than 90 day(s)' in res.output
    with app.app_context():
        assert Notification.query.count() == 1
