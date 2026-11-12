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
