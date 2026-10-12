"""Tests de l'edition des textes du site (app/site_text.py + /admin/texts).

    python -m pytest tests/test_site_text.py
    python tests/test_site_text.py        # sans pytest

Base SQLite en memoire, jamais instance/blog.db.
"""
import io
import json
import os
import re
import sys

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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db  # noqa: E402
from app.models import SiteText, SiteTextRevision, User  # noqa: E402
from app import site_text as st  # noqa: E402

app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False
app.config['ANTISPAM_ENABLED'] = False

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         'app', 'templates')


def fresh_db():
    """Base vide + un admin et un utilisateur. Renvoie (admin_id, user_id)."""
    ctx = app.app_context()
    ctx.push()
    db.session.remove()
    db.drop_all()
    db.create_all()
    admin = User(username='admin', password='x', is_admin=True)
    user = User(username='reader', password='x', is_admin=False)
    db.session.add_all([admin, user])
    db.session.commit()
    ids = (admin.id, user.id)
    ctx.pop()
    # compteurs de limitation (persistants) : on les remet a zero
    from app import routes
    routes.action_rate_limit_buckets.clear()
    return ids


def login(client, user_id):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


def admin_client():
    admin_id, _ = fresh_db()
    client = app.test_client()
    login(client, admin_id)
    return client, admin_id


def rows():
    return {r.key: r for r in SiteText.query.all()}


def fp_of(client, key, **params):
    html = client.get('/admin/texts', query_string=params).get_data(as_text=True)
    m = re.search(r'name="%s::fp" value="([^"]*)"' % re.escape(key), html)
    assert m, f'fingerprint de {key} absente'
    return m.group(1)


# ------------------------------------------------------------- unitaires

def test_render_rich():
    with app.test_request_context('/'):
        html = str(st.render_rich('a\r\n\r\nb'))
        assert html.count('<p>') == 2
        assert '<br>' in str(st.render_rich('a\nb'))
        assert '<script>' not in str(st.render_rich('<script>alert(1)</script>'))
        assert 'href="#"' in str(st.render_rich('[url=javascript:alert(1)]x[/url]'))
        assert 'href="#"' in str(st.render_rich('[url=data:image/png;base64,AA]x[/url]'))
        assert 'href="https://example.org"' in str(st.render_rich('[url=https://example.org]x[/url]'))


def test_normalize_and_override():
    assert st.normalize_text('  \r\n ') is None
    assert st.normalize_text(None) is None
    assert st.normalize_text('a\x00b\x1bc\r\nd') == 'abc\nd'
    default = st.DEFAULTS['nav.about']['en']
    assert st.effective_override('nav.about', 'en', default) is None
    assert st.effective_override('nav.about', 'en', default + '!') == default + '!'


def test_validate_value():
    assert st.validate_value('nav.about', 'en', 'x' * 501)
    assert st.validate_value('nav.about', 'en', 'x' * 500) is None
    assert st.validate_value('about.body', 'en', 'x' * 20001)
    assert st.validate_value('about.body', 'en', 'x' * 20000) is None
    assert st.validate_value('contact.email_address', 'en', 'not an email')
    assert st.validate_value('contact.email_address', 'en', 'me@example.org') is None
    assert st.validate_value('nav.about', 'en', 'two\nlines')
    assert st.validate_value('about.body', 'en', 'two\n\nparagraphs') is None


def test_get_text_resolution():
    fresh_db()
    with app.test_request_context('/?lang=fr'):
        assert st.get_text('nav.about') == st.DEFAULTS['nav.about']['fr']
        assert st.get_text('no.such.key') == 'no.such.key'
    with app.app_context():
        db.session.add(SiteText(key='nav.about', text_en='EN!', text_fr=None))
        db.session.commit()
    with app.test_request_context('/'):
        assert st.get_text('nav.about', 'en') == 'EN!'
        assert st.get_text('nav.about', 'fr') == st.DEFAULTS['nav.about']['fr']


def test_overrides_without_table_rolls_back():
    fresh_db()
    with app.test_request_context('/'):
        db.session.execute(db.text('DROP TABLE site_text_revision'))
        db.session.execute(db.text('DROP TABLE site_text'))
        db.session.commit()
        assert st._overrides() == {}
        assert st.get_text('nav.about', 'en') == st.DEFAULTS['nav.about']['en']
        # la session reste utilisable apres l'echec
        assert db.session.execute(db.text('SELECT 1')).scalar() == 1
    fresh_db()


def test_defaults_integrity():
    prefixes = {p for p, _ in st.GROUPS}
    for key, val in st.DEFAULTS.items():
        assert key.split('.')[0] in prefixes, key
        assert 'en' in val and 'fr' in val, key
    for key in st.RICH_KEYS:
        assert key in st.DEFAULTS
    usage = st.key_usage()
    assert usage, 'scan des gabarits vide'
    missing = [k for k in usage if k not in st.DEFAULTS]
    assert not missing, missing


def test_no_literal_placeholder_in_templates():
    bad = []
    for folder, _d, files in os.walk(TEMPLATES):
        for name in files:
            with open(os.path.join(folder, name), encoding='utf-8') as fh:
                for n, line in enumerate(fh, 1):
                    if 'form.' in line and '="{{ t(' in line:
                        bad.append(f'{name}:{n}')
    assert not bad, bad


# ----------------------------------------------------------------- routes

def test_non_admin_redirected():
    _, user_id = fresh_db()
    anon = app.test_client()
    reader = app.test_client()
    login(reader, user_id)
    for client in (anon, reader):
        for method, url in [('get', '/admin/texts'), ('post', '/admin/texts'),
                            ('get', '/admin/texts/history/nav.about'),
                            ('post', '/admin/texts/revert/1'),
                            ('get', '/admin/texts/export.json'),
                            ('post', '/admin/texts/import')]:
            resp = getattr(client, method)(url)
            assert resp.status_code == 302, (method, url, resp.status_code)
            assert urlparse_path(resp.headers['Location']) == '/', url


def urlparse_path(location):
    from urllib.parse import urlparse
    return urlparse(location).path


def test_save_creates_row_and_revision():
    client, admin_id = admin_client()
    fp = fp_of(client, 'nav.about')
    resp = client.post('/admin/texts', data={
        'nav.about::fp': fp, 'nav.about::en': 'About me', 'nav.about::fr': ''})
    assert resp.status_code == 302
    with app.app_context():
        row = rows()['nav.about']
        assert (row.text_en, row.text_fr, row.updated_by_id) == ('About me', None, admin_id)
        revs = SiteTextRevision.query.all()
        assert len(revs) == 1 and revs[0].changed_by_id == admin_id and revs[0].action == 'save'
        cols = {c.name for c in SiteTextRevision.__table__.columns}
        assert not any('ip' == c or c.startswith('ip_') or 'agent' in c for c in cols)


def test_equal_to_default_not_stored_and_crlf_normalized():
    client, _ = admin_client()
    default = st.DEFAULTS['nav.about']['en']
    client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': default,
        'nav.about::fr': ''})
    with app.app_context():
        assert 'nav.about' not in rows()
    client.post('/admin/texts', data={
        'about.body::fp': fp_of(client, 'about.body'),
        'about.body::en': 'one\r\n\r\ntwo', 'about.body::fr': ''})
    with app.app_context():
        assert rows()['about.body'].text_en == 'one\n\ntwo'
    html = client.get('/about').get_data(as_text=True)
    assert html.count('one</p>') == 1 and '<p>two</p>' in html


def test_conflict_returns_400_and_keeps_db():
    client, _ = admin_client()
    fp1 = fp_of(client, 'nav.about')
    with app.app_context():
        db.session.add(SiteText(key='nav.about', text_en='other admin', text_fr=None))
        db.session.commit()
    resp = client.post('/admin/texts', data={
        'nav.about::fp': fp1, 'nav.about::en': 'mine', 'nav.about::fr': ''})
    assert resp.status_code == 400
    assert 'other admin' in resp.get_data(as_text=True)
    with app.app_context():
        assert rows()['nav.about'].text_en == 'other admin'
        assert SiteTextRevision.query.count() == 0


def test_filter_does_not_delete_hidden_keys():
    client, _ = admin_client()
    with app.app_context():
        db.session.add(SiteText(key='home.hero.cta', text_en='Go', text_fr=None))
        db.session.commit()
    fp = fp_of(client, 'nav.about', group='nav')
    html = client.get('/admin/texts', query_string={'group': 'nav'}).get_data(as_text=True)
    assert 'home.hero.cta::fp' not in html
    resp = client.post('/admin/texts', data={
        'group': 'nav', 'nav.about::fp': fp, 'nav.about::en': 'About!', 'nav.about::fr': ''})
    assert resp.status_code == 302
    with app.app_context():
        r = rows()
        assert r['home.hero.cta'].text_en == 'Go'
        assert r['nav.about'].text_en == 'About!'


def test_preview_writes_nothing():
    client, _ = admin_client()
    resp = client.post('/admin/texts', data={
        'action': 'preview', 'about.body::fp': fp_of(client, 'about.body'),
        'about.body::en': 'Hello [b]bold[/b]\n\nSecond', 'about.body::fr': ''})
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'text-preview' in html and '<strong>bold</strong>' in html or '<b>bold</b>' in html
    assert 'Hello [b]bold[/b]' in html
    with app.app_context():
        assert not rows() and SiteTextRevision.query.count() == 0


def test_reset_deletes_row_and_logs_revision():
    client, _ = admin_client()
    client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': 'X', 'nav.about::fr': ''})
    resp = client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::reset': '1',
        'nav.about::en': 'X', 'nav.about::fr': ''})
    assert resp.status_code == 302
    with app.app_context():
        assert 'nav.about' not in rows()
        last = SiteTextRevision.query.order_by(SiteTextRevision.id.desc()).first()
        assert (last.action, last.text_en, last.text_fr) == ('reset', None, None)


def test_revert():
    client, _ = admin_client()
    client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': 'v1', 'nav.about::fr': ''})
    client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': 'v2', 'nav.about::fr': ''})
    with app.app_context():
        first = SiteTextRevision.query.order_by(SiteTextRevision.id).first().id
    assert client.get('/admin/texts/history/nav.about').status_code == 200
    resp = client.post(f'/admin/texts/revert/{first}')
    assert resp.status_code == 302
    with app.app_context():
        assert rows()['nav.about'].text_en == 'v1'
        last = SiteTextRevision.query.order_by(SiteTextRevision.id.desc()).first()
        assert last.action == 'revert' and last.text_en == 'v1'
    assert client.get('/admin/texts/history/unknown.key').status_code == 404


def test_export_import_roundtrip():
    client, _ = admin_client()
    client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': 'Ex', 'nav.about::fr': 'Fr'})
    resp = client.get('/admin/texts/export.json')
    assert resp.headers['Cache-Control'] == 'no-store'
    assert 'attachment' in resp.headers['Content-Disposition']
    payload = resp.get_data()
    data = json.loads(payload)
    assert data['format'] == 'site-text/1' and data['texts']['nav.about']['fr'] == 'Fr'

    with app.app_context():
        before = SiteTextRevision.query.count()

    def do_import(raw, name='t.json'):
        return client.post('/admin/texts/import',
                           data={'file': (io.BytesIO(raw), name)},
                           content_type='multipart/form-data')

    assert do_import(payload).status_code == 302
    with app.app_context():
        assert SiteTextRevision.query.count() == before  # 0 changement

    # cle inconnue : ignoree, le reste importe
    data['texts']['bogus.key'] = {'en': 'x', 'fr': None}
    data['texts']['nav.contact'] = {'en': 'Reach me', 'fr': None}
    do_import(json.dumps(data).encode())
    with app.app_context():
        r = rows()
        assert 'bogus.key' not in r and r['nav.contact'].text_en == 'Reach me'

    # invalide / trop gros / valeur trop longue : rien d'ecrit
    snapshot = None
    with app.app_context():
        snapshot = {k: (v.text_en, v.text_fr) for k, v in rows().items()}
    bad_json = do_import(b'{not json')
    too_big = do_import(b' ' * (256 * 1024 + 1))
    too_long = do_import(json.dumps({'format': 'site-text/1', 'texts': {
        'nav.login': {'en': 'fine', 'fr': None},
        'nav.logout': {'en': 'x' * 501, 'fr': None}}}).encode())
    for r in (bad_json, too_big, too_long):
        assert r.status_code == 302
    with app.app_context():
        assert {k: (v.text_en, v.text_fr) for k, v in rows().items()} == snapshot


def test_retention():
    client, _ = admin_client()
    from app import routes
    for i in range(35):
        routes.action_rate_limit_buckets.clear()  # 30 ecritures/min sinon
        client.post('/admin/texts', data={
            'nav.about::fp': fp_of(client, 'nav.about'),
            'nav.about::en': f'v{i}', 'nav.about::fr': ''})
    with app.app_context():
        revs = SiteTextRevision.query.filter_by(key='nav.about').order_by(SiteTextRevision.id).all()
        assert len(revs) == 30 and revs[-1].text_en == 'v34'


def test_rate_limit_blocks_31st_post():
    from app import routes
    client, _ = admin_client()
    routes.action_rate_limit_buckets.clear()
    codes = []
    for i in range(31):
        client.post('/admin/texts', data={
            'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': f'r{i}',
            'nav.about::fr': ''})
        with app.app_context():
            codes.append(rows()['nav.about'].text_en)
    assert codes[-1] == codes[-2]  # la 31e ecriture n'est pas passee


def test_validation_error_400():
    client, _ = admin_client()
    resp = client.post('/admin/texts', data={
        'nav.about::fp': fp_of(client, 'nav.about'), 'nav.about::en': 'x' * 501,
        'nav.about::fr': ''})
    assert resp.status_code == 400
    with app.app_context():
        assert not rows()


def test_public_pages_and_placeholders():
    client, _ = admin_client()
    anon = app.test_client()
    for url in ['/', '/about', '/contact', '/donate', '/login', '/register', '/about?lang=fr']:
        assert anon.get(url).status_code == 200, url
    html = anon.get('/login?lang=en').get_data(as_text=True)
    assert 'placeholder="Username"' in html
    assert 'placeholder="{{' not in html
    assert 'depressedyoungman' in anon.get('/about').get_data(as_text=True)


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
