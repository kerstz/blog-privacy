"""Regression tests of the 2026-11 audit (agent audit-2026-11-11)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_security_fixes import app, make_post, make_user, reset  # noqa: E402
from app import db, routes  # noqa: E402
from app.models import Comment, Message, Post  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------- attachment lookup: LIKE wildcards

def test_attachment_lookup_treats_underscore_and_percent_literally():
    """"_" and "%" in a requested file name must not act as SQL LIKE wildcards:
    otherwise the access check could be decided on another user's message."""
    reset()
    alice = make_user('alice')
    admin = make_user('boss', admin=True)
    with app.app_context():
        db.session.add(Message(sender_id=alice, receiver_id=admin, content='x',
                               file_path='uploads/chat_aaaa.webp.enc', file_type='image'))
        db.session.commit()
        assert routes._attachment_message('chat_aaaa.webp.enc') is not None
        assert routes._attachment_message('chat_a_aa.webp.enc') is None
        assert routes._attachment_message('chat_a%.webp.enc') is None
        assert routes._attachment_message('%.enc') is None


# ------------------------------------------------- public profile: drafts do not leak

def test_profile_hides_comments_on_unpublished_posts():
    reset()
    admin = make_user('boss', admin=True)
    bob = make_user('bob')
    public_id = make_post(admin, published=True, title='PublicTitle')
    secret_id = make_post(admin, published=True, title='SecretDraftTitle')
    with app.app_context():
        db.session.add(Comment(content='visible comment', content_format='bbcode',
                               post_id=public_id, author_id=bob))
        db.session.add(Comment(content='comment on later draft', content_format='bbcode',
                               post_id=secret_id, author_id=bob))
        post = db.session.get(Post, secret_id)
        post.is_published = False
        post.is_draft = True
        db.session.commit()
    html = app.test_client().get(f'/profile/{bob}').get_data(as_text=True)
    assert 'visible comment' in html
    assert 'SecretDraftTitle' not in html
    assert 'comment on later draft' not in html


# ------------------------------------------------- health check

def test_healthz_ok_is_anonymous_minimal_and_sets_no_cookie():
    reset()
    resp = app.test_client().get('/healthz')
    assert resp.status_code == 200
    assert resp.get_data(as_text=True).strip() == 'ok'
    assert resp.headers['Cache-Control'] == 'no-store'
    assert 'Set-Cookie' not in resp.headers


def test_healthz_reports_unavailable_without_details(monkeypatch):
    reset()

    def boom(*args, **kwargs):
        raise RuntimeError('secret-db-path /srv/blog/instance/blog.db')

    monkeypatch.setattr(db.session, 'execute', boom)
    resp = app.test_client().get('/healthz')
    assert resp.status_code == 503
    body = resp.get_data(as_text=True)
    assert body.strip() == 'unavailable'
    assert 'secret-db-path' not in body


# ------------------------------------------------- systemd hardening

def test_blog_service_is_hardened():
    unit = open(os.path.join(REPO, 'deploy', 'blog.service')).read()
    for directive in ('NoNewPrivileges=true', 'ProtectSystem=strict', 'PrivateTmp=true',
                      'PrivateDevices=true', 'ProtectHome=true', 'RestrictNamespaces=true',
                      'RestrictRealtime=true', 'LockPersonality=true', 'UMask=0077',
                      'SystemCallArchitectures=native', 'ProtectKernelLogs=true'):
        assert re.search(rf'^{re.escape(directive)}\s*$', unit, re.M), directive
    assert re.search(r'^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\s*$', unit, re.M)
    # a missing optional directory must not stop the service with ProtectSystem=strict
    assert '-/srv/blog/backups' in unit
