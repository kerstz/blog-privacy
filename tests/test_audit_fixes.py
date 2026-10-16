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
