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
