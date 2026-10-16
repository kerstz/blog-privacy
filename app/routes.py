"""Web routes (public pages, auth, chat, admin panel) and SocketIO handlers."""
from flask import (send_file, render_template, url_for, flash, redirect, request, abort,
                   send_from_directory, session, Response)
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, socketio
from app.forms import (LoginForm, RegistrationForm, PostForm, CommentForm, EmptyForm, BannerForm,
                       StaticPageForm, ContactForm, ProfileEditForm, TOTPSetupForm, TOTPDisableForm,
                       TOTPVerifyForm, ChangePasswordForm, ReauthForm, DeleteAccountForm,
                       SiteTextImportForm)
from app.models import (User, Post, Comment, Revision, Banner, StaticPage, Message, Donor, Like,
                        Notification, ContactMessage, Tag)
from app.site_text import get_text
from app.utils import (client_ip_is_meaningful, rate_limit, hit_rate_limit, html_to_text, anonymous_client_key,
                       hashed_key, record_failure, too_many_failures, clear_failures,
                       _RATE_LIMIT_STORE, _FAILURE_STORE)
from datetime import datetime, timedelta
from flask_socketio import emit
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
import re
import mimetypes
from cryptography.fernet import InvalidToken
import json
import os
import base64
import math
import time
import pyotp
import io
from flask_socketio import join_room, disconnect
from app import mobile_api  # noqa: F401  (registers the /api/admin/mobile routes)
from app.services import (
    apply_post_taxonomy,
    slugify,
    ENCRYPTED_SUFFIX,
    read_upload_bytes,
    upload_display_name,
    export_user_data,
    generate_recovery_codes,
    invalidate_other_sessions,
    recovery_codes_left,
    security_alert,
    verify_second_factor,
    CHAT_ALLOWED_EXTENSIONS,
    IMAGE_EXTENSIONS,
    MAX_IMAGE_PIXELS,
    MAX_UPLOAD_BYTES,
    PROFILE_ALLOWED_EXTENSIONS,
    UPLOAD_FILE_ALLOWED_EXTENSIONS,
    UPLOAD_FOLDER,
    UploadRefused,
    _action_rate_limited,
    _absolute_upload_path as _service_upload_path,
    _check_user_password,
    _conversation_latest_message_id,
    _delete_post_and_children,
    _delete_user_and_data,
    _file_ext,
    _get_admin_user_id,
    _notify_admins_new_message,
    _notify_user,
    _remove_upload_file,
    _start_fresh_session,
    _store_totp_secret,
    _store_upload,
    _totp_secret,
    _user_conversation_query,
    _user_room,
    _validate_uploaded_file,
    _verify_totp_once,
    _visible_posts_query,
    admin_required,
    check_and_award_badges,
    create_default_badges,
    get_file_type,
    publish_mobile_event,
    screen_uploaded_image,
    serialize_chat_message,
    strip_image_metadata,
)

# Backward-compatible handle: `.clear()` resets the persistent rate limiter.
action_rate_limit_buckets = _RATE_LIMIT_STORE


def _uploads_root():
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                                        UPLOAD_FOLDER))


def _absolute_upload_path(stored_path):
    """Absolute path of an attachment, bounded to the uploads folder."""
    return _service_upload_path(stored_path, root=_uploads_root())


def _published_posts_query():
    """Public listings: published posts only, for everybody (admins included;
    they manage drafts and scheduled posts in the admin panel)."""
    return Post.query.filter(Post.is_published.is_(True))


def _require_visible_post(post):
    """404 for a draft or a scheduled post, except for an admin."""
    if post.is_published:
        return
    if current_user.is_authenticated and current_user.is_admin:
        return
    abort(404)


# ---------------------------------------------------------------- hooks
@app.before_request
def enforce_ban():
    """Log a banned account out from its very next request.

    Without this check a banned user would stay active until the session
    cookie expires (up to four hours).
    """
    if getattr(current_user, 'is_authenticated', False) and getattr(current_user, 'is_banned', False):
        logout_user()
        session.clear()
        if request.endpoint not in ('static', 'login'):
            flash('This account has been suspended.', 'danger')
            return redirect(url_for('login'))


@app.before_request
def enforce_password_change():
    """Send the user to the password change page while it is required.

    Without this guard `must_change_password` would be just a column: the
    account created by the deployment script would stay usable with the
    password printed in a file.
    """
    if not getattr(current_user, 'is_authenticated', False):
        return
    if not getattr(current_user, 'must_change_password', False):
        return
    if request.endpoint in ('change_password', 'logout', 'static', 'static_v'):
        return
    return redirect(url_for('change_password'))


@app.before_request
def publish_due_scheduled_posts():
    """Publish the posts whose scheduled date has passed."""
    from app.utils import publish_scheduled_posts
    publish_scheduled_posts()


# Optional .onion address, e.g. ONION_ADDRESS=abcd...xyz.onion (56 chars + .onion)
ONION_ADDRESS = (os.environ.get('ONION_ADDRESS') or '').strip().lower()
if ONION_ADDRESS and not re.fullmatch(r'[a-z2-7]{56}\.onion', ONION_ADDRESS):
    raise RuntimeError("ONION_ADDRESS must be a v3 onion address like '<56 chars>.onion'")


# Content security policy: no JavaScript at all, no third-party resource (each
# request to a third party would reveal the reader's IP address, the URL and
# the User-Agent to it). <style> elements are blocked; style="" attributes stay
# allowed (sanitized BBCode colors/sizes).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "media-src 'self'; "
    "style-src 'self'; "
    "style-src-attr 'unsafe-inline'; "
    "script-src 'none'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "frame-src 'none'; "
    "worker-src 'none'; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
    "form-action 'self'"
)


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # no-referrer: no URL of this site must leak to an external site when a
    # reader follows an outgoing link.
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault(
        'Permissions-Policy',
        'geolocation=(), microphone=(), camera=(), payment=(), usb=(), '
        'magnetometer=(), gyroscope=(), accelerometer=(), interest-cohort=()'
    )
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
    response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)

    # HSTS only on an effective HTTPS connection (or when forced): sending it
    # over plain HTTP has no effect, and sending it wrongly can lock a test
    # site out.
    if request.is_secure or app.config.get('SESSION_COOKIE_SECURE') \
            or os.environ.get('FORCE_HSTS', '').lower() in ('1', 'true', 'yes'):
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
    # Tor: advertise the .onion mirror to Tor Browser users (ONION_ADDRESS env)
    if ONION_ADDRESS and not request.host.endswith('.onion'):
        response.headers.setdefault('Onion-Location', f"http://{ONION_ADDRESS}{request.full_path.rstrip('?')}")
    # Pages for logged-in users must never be stored by shared caches.
    if current_user.is_authenticated and 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store'
    # Do not advertise the server stack.
    response.headers['Server'] = 'server'
    return response


@app.route('/admin/flag_image/<int:message_id>', methods=['POST'])
@admin_required
def flag_message_image(message_id):
    """Signale la piece jointe d'un message : bannit l'auteur, retient le hash.

    C'est ainsi que la liste de blocage se remplit. Les bases de reference
    (NCMEC, PhotoDNA, IWF) ne sont pas distribuees publiquement ; ici la liste
    est le produit des decisions de moderation prises sur ce site. Une fois une
    image signalee, toute nouvelle tentative de la televerser — meme ré-encodee
    ou redimensionnee — est refusee automatiquement.
    """
    from app.image_safety import (dhash_of_path, format_dhash, quarantine_file,
                                  sha256_of_file)
    from app.models import BlockedImageHash, BlockedUploadEvent

    form = EmptyForm()
    if not form.validate_on_submit():
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('admin_chat'))

    message = Message.query.get_or_404(message_id)
    if not message.file_path:
        flash('This message has no attachment.', 'danger')
        return redirect(url_for('admin_chat_user', user_id=message.sender_id))

    path = _absolute_upload_path(message.file_path)
    if not path or not os.path.exists(path):
        flash('The file is no longer on disk.', 'danger')
        return redirect(url_for('admin_chat_user', user_id=message.sender_id))

    digest = sha256_of_file(path)
    try:
        perceptual = format_dhash(dhash_of_path(path))
    except Exception:
        # Fichier non decodable comme image : on retient au moins le SHA-256.
        perceptual = None

    entry = BlockedImageHash.query.filter_by(sha256=digest).first()
    if entry is None:
        entry = BlockedImageHash(
            sha256=digest,
            dhash=perceptual,
            label=f'Flagged by {current_user.username} on message {message.id}',
        )
        db.session.add(entry)
        db.session.flush()

    author = message.sender
    banned_name = None
    if author and not author.is_admin:
        author.is_banned = True
        author.banned_at = datetime.utcnow()
        author.ban_reason = 'Flagged image upload'
        author.rotate_session_token()
        banned_name = author.username

    quarantined = quarantine_file(path, reason=f'flagged by admin {current_user.id}')

    db.session.add(BlockedUploadEvent(
        user_id=author.id if author else None,
        matched_hash_id=entry.id,
        distance=0,
        sha256=digest,
        quarantine_name=quarantined,
    ))

    # Le message perd sa piece jointe : le fichier n'est plus servable.
    message.file_path = None
    message.file_type = None
    db.session.commit()

    app.logger.warning('Admin %s flagged image on message %s (user %s)',
                       current_user.id, message.id, author.id if author else None)

    if banned_name:
        flash(f'Image blocked, hash recorded, and {banned_name} was banned.', 'success')
    else:
        flash('Image blocked and hash recorded.', 'success')
    return redirect(url_for('admin_moderation'))


@app.route('/admin/moderation', methods=['GET'])
@admin_required
def admin_moderation():
    """Liste de blocage, televersements refuses et comptes bannis."""
    from app.models import BlockedImageHash, BlockedUploadEvent

    return render_template(
        'admin_moderation.html',
        form=EmptyForm(),
        blocked=BlockedImageHash.query.order_by(BlockedImageHash.added_at.desc()).all(),
        events=BlockedUploadEvent.query.order_by(BlockedUploadEvent.created_at.desc()).limit(100).all(),
        banned=User.query.filter_by(is_banned=True).order_by(User.banned_at.desc()).all(),
    )


@app.route('/admin/moderation/unblock/<int:hash_id>', methods=['POST'])
@admin_required
def admin_unblock_hash(hash_id):
    """Retire une empreinte de la liste — pour corriger un faux positif."""
    from app.models import BlockedImageHash

    if not EmptyForm().validate_on_submit():
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('admin_moderation'))

    entry = BlockedImageHash.query.get_or_404(hash_id)
    db.session.delete(entry)
    db.session.commit()
    flash('Hash removed from the block list.', 'success')
    return redirect(url_for('admin_moderation'))


@app.route('/admin/moderation/unban/<int:user_id>', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    """Leve un bannissement."""
    if not EmptyForm().validate_on_submit():
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('admin_moderation'))

    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.banned_at = None
    user.ban_reason = None
    db.session.commit()
    flash(f'{user.username} can sign in again.', 'success')
    return redirect(url_for('admin_moderation'))


SITE_TEXT_STATUSES = ('all', 'edited', 'default', 'partial', 'unused', 'orphan')


def _site_text_filters(source):
    """Filtres de l'editeur (q, group, status), valides et bornes."""
    from app.site_text import GROUPS
    q = (source.get('q') or '').strip()[:100]
    group = source.get('group') or ''
    if group not in {prefix for prefix, _label in GROUPS}:
        group = ''
    status = source.get('status') or 'all'
    if status not in SITE_TEXT_STATUSES:
        status = 'all'
    return q, group, status


def _site_text_context(rows, q, group, status, **extra):
    """Contexte du gabarit de l'editeur : cles visibles, compteurs, etat."""
    from app.site_text import (DEFAULTS, GROUPS, LANGUAGES, RICH_KEYS, fingerprint,
                               key_usage, orphan_keys)

    usage = key_usage()
    orphans = orphan_keys(rows)

    def is_partial(row):
        return row is not None and (row.text_en is None) != (row.text_fr is None)

    counts = {
        'total': len(DEFAULTS),
        'edited': sum(1 for k in DEFAULTS if k in rows),
        'partial': sum(1 for k in DEFAULTS if is_partial(rows.get(k))),
        'unused': sum(1 for k in DEFAULTS if k not in usage),
        'orphan': len(orphans),
    }

    needle = q.lower()

    def visible(key):
        row = rows.get(key)
        known = key in DEFAULTS
        if group and key.split('.')[0] != group:
            return False
        if status == 'edited' and not (known and row):
            return False
        if status == 'default' and not (known and not row):
            return False
        if status == 'partial' and not is_partial(row):
            return False
        if status == 'unused' and not (known and key not in usage):
            return False
        if status == 'orphan' and known:
            return False
        if needle:
            haystack = [key]
            if known:
                haystack += [DEFAULTS[key].get('en') or '', DEFAULTS[key].get('fr') or '']
            if row:
                haystack += [row.text_en or '', row.text_fr or '']
            if not any(needle in h.lower() for h in haystack):
                return False
        return True

    groups = []
    for prefix, label in GROUPS:
        keys = sorted(k for k in DEFAULTS if k.split('.')[0] == prefix and visible(k))
        if keys:
            groups.append((prefix, label, keys))
    shown_orphans = [k for k in orphans if visible(k)] if status in ('all', 'orphan') else []

    context = dict(
        form=EmptyForm(),
        import_form=SiteTextImportForm(),
        groups=groups,
        orphans=shown_orphans,
        defaults=DEFAULTS,
        overrides=rows,
        languages=LANGUAGES,
        rich_keys=RICH_KEYS,
        usage=usage,
        counts=counts,
        group_options=GROUPS,
        status_options=SITE_TEXT_STATUSES,
        q=q, group=group, status=status,
        fps={k: fingerprint(r) for k, r in rows.items()},
        fingerprint=fingerprint,
        submitted={}, previews={}, errors={}, conflicts=[],
        is_partial=is_partial,
    )
    context.update(extra)
    return context


@app.route('/admin/texts', methods=['GET', 'POST'])
@admin_required
def manage_site_texts():
    """Editeur des textes fixes du site, en francais et en anglais.

    Un champ laisse vide n'ecrit pas une chaine vide : il supprime la
    personnalisation et le texte revient a sa valeur par defaut.

    Chaque cle affichee porte une empreinte (`::fp`) de son etat au moment du
    rendu. A l'enregistrement, seules les cles dont le champ a change sont
    ecrites, et une cle modifiee entre-temps par quelqu'un d'autre est signalee
    comme conflit au lieu d'etre ecrasee. Une cle absente du formulaire (filtre
    actif) n'est jamais touchee.
    """
    from app.models import SiteText
    from app.site_text import (DEFAULTS, LANGUAGES, RICH_KEYS, apply_change,
                               effective_override, fingerprint, fingerprint_values,
                               orphan_keys, render_rich, validate_value)

    rows = {row.key: row for row in SiteText.query.all()}

    if request.method == 'GET':
        q, group, status = _site_text_filters(request.args)
        return render_template('manage_site_texts.html',
                               **_site_text_context(rows, q, group, status))

    q, group, status = _site_text_filters(request.form)
    redirect_args = {k: v for k, v in (('q', q), ('group', group),
                                       ('status', status if status != 'all' else ''))
                     if v}

    if not EmptyForm().validate_on_submit():
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('manage_site_texts', **redirect_args))
    if _action_rate_limited('site_texts', 30, 60):
        flash('Too many changes in a short time. Please wait a minute.', 'danger')
        return redirect(url_for('manage_site_texts', **redirect_args))

    action = request.form.get('action', 'save')
    if action not in ('save', 'preview'):
        action = 'save'

    changes = []      # (key, en, fr, action)
    errors = {}
    conflicts = []
    previews = {}
    submitted = {}
    fps = {}

    for key in list(DEFAULTS) + orphan_keys(rows):
        fp_form = request.form.get(f'{key}::fp')
        if fp_form is None:
            continue  # cle non affichee (filtre) : surtout ne pas y toucher
        fps[key] = fp_form
        known = key in DEFAULTS
        row = rows.get(key)

        if request.form.get(f'{key}::reset'):
            target, act = (None, None), 'reset'
        elif known:
            target = tuple(effective_override(key, lang, request.form.get(f'{key}::{lang}'))
                           for lang in ('en', 'fr'))
            act = 'save'
            submitted[key] = {lang: request.form.get(f'{key}::{lang}') or ''
                              for lang in LANGUAGES}
        else:
            continue  # orphelin : reset uniquement

        target_fp = fingerprint_values(*target)
        if target_fp == fp_form:
            continue  # rien touche
        if target_fp == fingerprint(row):
            continue  # deja a jour
        if fp_form != fingerprint(row):
            conflicts.append(key)
            continue

        problems = [m for m in (validate_value(key, lang, val)
                                for lang, val in zip(('en', 'fr'), target)) if m]
        if problems:
            errors[key] = problems
            continue

        changes.append((key, target[0], target[1], act))
        if key in RICH_KEYS:
            previews[key] = {lang: render_rich(val) for lang, val in zip(('en', 'fr'), target)
                             if val}

    if action == 'preview' or errors or conflicts:
        if errors or conflicts:
            flash('Nothing was saved. Fix the highlighted texts and try again.', 'danger')
        else:
            flash('Preview only: nothing was saved.', 'info')
        context = _site_text_context(rows, q, group, status, submitted=submitted,
                                     previews=previews, errors=errors,
                                     conflicts=conflicts)
        context['fps'] = {**context['fps'], **fps}
        return render_template('manage_site_texts.html', **context), \
            (400 if (errors or conflicts) else 200)

    changed = 0
    for key, en, fr, act in changes:
        if apply_change(key, en, fr, act, current_user.id):
            changed += 1
    db.session.commit()
    flash(f'{changed} text(s) updated.' if changed else 'No changes to save.',
          'success' if changed else 'info')
    return redirect(url_for('manage_site_texts', **redirect_args))


@app.route('/admin/texts/history/<path:key>')
@admin_required
def manage_site_text_history(key):
    """Historique d'une cle : etat courant, defauts, dernieres revisions."""
    from app.models import SiteText, SiteTextRevision
    from app.site_text import DEFAULTS, LANGUAGES, REVISIONS_KEPT

    row = SiteText.query.filter_by(key=key).first()
    revisions = (SiteTextRevision.query.filter_by(key=key)
                 .order_by(SiteTextRevision.id.desc()).limit(REVISIONS_KEPT).all())
    if key not in DEFAULTS and row is None and not revisions:
        abort(404)
    return render_template('site_text_history.html', form=EmptyForm(), key=key,
                           row=row, default=DEFAULTS.get(key), revisions=revisions,
                           languages=LANGUAGES)


@app.route('/admin/texts/revert/<int:rev_id>', methods=['POST'])
@admin_required
def revert_site_text(rev_id):
    """Restaure l'etat d'une revision (ecrit lui-meme une nouvelle revision)."""
    from app.models import SiteTextRevision
    from app.site_text import apply_change, effective_override, validate_value

    rev = SiteTextRevision.query.get_or_404(rev_id)
    back = url_for('manage_site_text_history', key=rev.key)

    if not EmptyForm().validate_on_submit():
        flash('Session expired. Please try again.', 'danger')
        return redirect(back)
    if _action_rate_limited('site_texts', 30, 60):
        flash('Too many changes in a short time. Please wait a minute.', 'danger')
        return redirect(back)

    en = effective_override(rev.key, 'en', rev.text_en)
    fr = effective_override(rev.key, 'fr', rev.text_fr)
    problems = [m for m in (validate_value(rev.key, 'en', en),
                            validate_value(rev.key, 'fr', fr)) if m]
    if problems:
        flash('This version can no longer be restored: ' + ' '.join(problems), 'danger')
        return redirect(back)

    if apply_change(rev.key, en, fr, 'revert', current_user.id):
        db.session.commit()
        flash('Version restored.', 'success')
    else:
        flash('Already at this version.', 'info')
    return redirect(back)


@app.route('/admin/texts/export.json')
@admin_required
def export_site_texts():
    """Export JSON des seules personnalisations (pas les defauts)."""
    from app.models import SiteText

    texts = {row.key: {'en': row.text_en, 'fr': row.text_fr}
             for row in SiteText.query.order_by(SiteText.key).all()}
    body = json.dumps({'format': 'site-text/1', 'texts': texts},
                      ensure_ascii=False, indent=2, sort_keys=True)
    return Response(body, mimetype='application/json', headers={
        'Content-Disposition': 'attachment; filename=site-texts.json',
        'Cache-Control': 'no-store',
    })


@app.route('/admin/texts/import', methods=['POST'])
@admin_required
def import_site_texts():
    """Import JSON : tout ou rien, cles inconnues ignorees et signalees."""
    from app.site_text import DEFAULTS, apply_change, effective_override, validate_value

    back = url_for('manage_site_texts')
    form = SiteTextImportForm()
    if not form.validate_on_submit():
        flash('Choose a .json file exported from this page.', 'danger')
        return redirect(back)
    if _action_rate_limited('site_texts', 30, 60):
        flash('Too many changes in a short time. Please wait a minute.', 'danger')
        return redirect(back)

    limit = 256 * 1024
    raw = form.file.data.read(limit + 1)
    if len(raw) > limit:
        flash('File too large (256 KB maximum).', 'danger')
        return redirect(back)
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        flash('Invalid JSON file.', 'danger')
        return redirect(back)
    texts = payload.get('texts') if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get('format') != 'site-text/1' \
            or not isinstance(texts, dict):
        flash('Unrecognised file format (expected "site-text/1").', 'danger')
        return redirect(back)

    problems = []
    skipped = 0
    planned = []
    for key, entry in texts.items():
        if key not in DEFAULTS:
            skipped += 1
            continue
        if not isinstance(entry, dict):
            problems.append(f'{key}: invalid entry.')
            continue
        values = []
        for lang in ('en', 'fr'):
            value = entry.get(lang)
            if value is not None and not isinstance(value, str):
                problems.append(f'{key}: {lang.upper()} must be text or null.')
                break
            value = effective_override(key, lang, value)
            message = validate_value(key, lang, value)
            if message:
                problems.append(f'{key}: {message}')
                break
            values.append(value)
        else:
            planned.append((key, values[0], values[1]))

    if problems:
        shown = ' | '.join(problems[:5])
        more = f' (+{len(problems) - 5} more)' if len(problems) > 5 else ''
        flash(f'Import refused, nothing was written. {shown}{more}', 'danger')
        return redirect(back)

    imported = sum(1 for key, en, fr in planned
                   if apply_change(key, en, fr, 'import', current_user.id))
    db.session.commit()
    flash(f'{imported} imported, {skipped} unknown key(s) skipped.',
          'success' if imported else 'info')
    return redirect(back)


@app.route('/robots.txt')
def robots_txt():
    """Decourage l'indexation et l'archivage automatique du site."""
    body = (
        "User-agent: *\n"
        "Disallow: /chat\n"
        "Disallow: /admin\n"
        "Disallow: /uploads/\n"
        "Disallow: /profile/\n"
        "Disallow: /notifications\n"
        "Disallow: /api/\n"
    )
    return Response(body, mimetype='text/plain')


def wait_for_conversation_message(admin_id, user_id, last_seen_id, timeout_seconds=25):
    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        latest_id = _conversation_latest_message_id(admin_id, user_id)
        if latest_id > last_seen_id:
            return True

        time.sleep(1)

    return False


@app.route('/')
def index():
    posts = _published_posts_query().order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


# About Page
@app.route('/about')
def about():
    return render_template('about.html')


# Editor Help Page
@app.route('/editor_help')
def editor_help():
    return render_template('editor_help.html')


# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        if _action_rate_limited('contact_submit', max_calls=8, window_seconds=300):
            flash('Too many contact attempts. Please wait a bit.', 'danger')
            return redirect(url_for('contact'))
        contact_msg = ContactMessage(
            name=form.name.data.strip(),
            email=form.email.data.strip(),
            message=form.message.data.strip()
        )
        db.session.add(contact_msg)
        db.session.commit()
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    _flash_antispam_errors(form)
    return render_template('contact.html', form=form)


# View a Blog Post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    form = CommentForm()
    # Increment view counter once per session
    if request.method == 'GET':
        viewed_posts = session.get('viewed_posts', [])
        if post_id not in viewed_posts:
            post.views_count = (post.views_count or 0) + 1
            db.session.commit()
            # keep the (client-side) session cookie small
            viewed_posts = (viewed_posts + [post_id])[-100:]
            session['viewed_posts'] = viewed_posts

    if form.validate_on_submit():
        if current_user.is_authenticated:
            if _action_rate_limited('comment_submit', max_calls=12, window_seconds=300):
                flash('Too many comments in a short time. Please slow down.', 'danger')
                return redirect(url_for('post_detail', post_id=post.id))
            content = form.content.data.strip()
            if content:
                # Plain text + BBCode: converted (and escaped) at render time by
                # the |comment_html filter.
                comment = Comment(content=content, content_format='bbcode',
                                  post_id=post.id, author_id=current_user.id)
                db.session.add(comment)
                db.session.commit()
                
                # Add experience points for commenting
                current_user.add_experience(3)
                
                # Create notification for post author
                if post.author_id != current_user.id:
                    notification = Notification(
                        user_id=post.author_id,
                        type='comment',
                        title='New comment!',
                        message=f'Someone commented on your article "{post.title}"',
                        related_post_id=post.id,
                        related_comment_id=comment.id
                    )
                    db.session.add(notification)
                    
                    _notify_user(post.author_id, {
                        'type': 'comment',
                        'title': 'New comment!',
                        'message': f'Someone commented on your article "{post.title}"',
                    })
                
                # Check and award badges
                check_and_award_badges(current_user)
                
                db.session.commit()
                flash('Your comment has been posted!', 'success')
            else:
                flash('Comment cannot be empty.', 'danger')
        else:
            flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('post_detail', post_id=post.id))
    _flash_antispam_errors(form)

    return render_template('post_detail.html', post=post, form=form)


# Register a User
@app.route('/register', methods=['GET', 'POST'])
@rate_limit('register', max_calls=10, window_seconds=3600)
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    _flash_antispam_errors(form)

    return render_template('register.html', title='Register', form=form)


def _flash_antispam_errors(form):
    """Anti-spam fields are invisible: surface their errors as flash messages."""
    if request.method == 'POST':
        for name in ('form_ts', 'website'):
            field = getattr(form, name, None)
            for error in (field.errors if field is not None else []):
                flash(error, 'danger')


def _login_failure_key(username):
    return 'login:' + hashed_key((username or '').strip().lower())


# Failed attempts: per username (10 in 15 min, also for unknown usernames: no
# enumeration) and per client (5 in 5 min). Past either limit the answer is the
# same generic "Login failed" page (200, no redirect) and bcrypt is not run.
LOGIN_USER_MAX_FAILURES = (10, 900)
LOGIN_CLIENT_MAX_FAILURES = (5, 300)


@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', max_calls=30, window_seconds=300,
            key_func=lambda: (request.form.get('username') or '').strip().lower() or 'empty')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = (form.username.data or '').strip()
        fkey = _login_failure_key(username)
        # The per-client lock only makes sense when the IP identifies the
        # visitor; behind an onion service it would be global (H1). The
        # per-username lock stays the brute-force protection.
        use_client_lock = client_ip_is_meaningful()
        ckey = 'login_client:' + anonymous_client_key()
        if too_many_failures(fkey, *LOGIN_USER_MAX_FAILURES) or \
                (use_client_lock and too_many_failures(ckey, *LOGIN_CLIENT_MAX_FAILURES)):
            flash('Login failed. Check your username and password.', 'danger')
            return render_template('login.html', title='Login', form=form)

        user = User.query.filter_by(username=username).first()
        # One bcrypt check is always made, even for an unknown user, so response
        # timing does not reveal which usernames exist.
        if user and _check_user_password(user, form.password.data):
            # The "suspended" status is only revealed after the password:
            # otherwise it would allow enumerating banned accounts.
            if user.is_banned:
                flash('This account has been suspended.', 'danger')
                return render_template('login.html', title='Login', form=form)
            clear_failures(fkey)
            remember = bool(form.remember_me.data)
            _start_fresh_session()
            if user.totp_enabled:
                # Store pre-auth state in session; do NOT log in yet
                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_remember'] = remember
                session['pre_2fa_at'] = int(time.time())
                return redirect(url_for('login_totp'))
            login_user(user, remember=remember)
            if user.is_admin:
                security_alert(f"admin login: @{user.username} (without 2FA!)")
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        if not user:
            _check_user_password(None, form.password.data)
        record_failure(fkey)
        if use_client_lock:
            record_failure(ckey)
        if user and user.is_admin and hit_rate_limit(f"alert_admin_fail:{user.id}", 1, 900) is False:
            security_alert(f"failed login on admin account @{user.username}")
        flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)


PRE_2FA_MAX_AGE = 300


def _clear_pre_2fa():
    for key in ('pre_2fa_user_id', 'pre_2fa_remember', 'pre_2fa_at'):
        session.pop(key, None)


# TOTP second-step verification
@app.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """Second step: verify the 6-digit TOTP (or a recovery code) after the password."""
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        # No pending pre-auth: back to login
        return redirect(url_for('login'))

    # The "password was valid" state expires: it must not survive for hours.
    started = session.get('pre_2fa_at')
    if not isinstance(started, int) or int(time.time()) - started > PRE_2FA_MAX_AGE:
        _clear_pre_2fa()
        flash('The verification step expired. Please sign in again.', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled or user.is_banned:
        _clear_pre_2fa()
        return redirect(url_for('login'))

    form = TOTPVerifyForm()
    if form.validate_on_submit():
        # 5 failures per 5 min per account, counted server-side: the session
        # cookie is replayable by the client, so a counter living in it could
        # be bypassed.
        if hit_rate_limit(f"totp_fail:{user.id}", 5, 300, record=False):
            _clear_pre_2fa()
            flash('Too many invalid codes. Please log in again later.', 'danger')
            return redirect(url_for('login'))
        if verify_second_factor(user, form.code.data):
            remember = session.get('pre_2fa_remember', False)
            _start_fresh_session()
            login_user(user, remember=remember)
            if user.is_admin:
                security_alert(f"admin login: @{user.username}")
            left = recovery_codes_left(user)
            if user.recovery_codes is not None and left <= 2:
                flash(f"Only {left} recovery code(s) left: generate new ones in your account security page.", "warning")
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            hit_rate_limit(f"totp_fail:{user.id}", 5, 300)
            if user.is_admin and hit_rate_limit(f"alert_totp_fail:{user.id}", 1, 900, record=True) is False:
                security_alert(f"wrong 2FA code for admin @{user.username} (password was correct!)")
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('login_totp.html', form=form)


# Logout a User
@app.route('/logout', methods=['POST'])
def logout():
    # POST + CSRF token: a third-party page cannot log users out
    _clear_pre_2fa()
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


def _conversations_awaiting_reply(admin_id):
    """Conversations dont le dernier message vient du lecteur.

    C'est le seul signal fiable ici : `Message` n'a pas d'indicateur de lecture,
    mais si le dernier message d'un fil n'est pas de l'admin, personne n'a
    encore repondu.
    """
    pending = 0
    for user in User.query.filter(User.is_admin.is_(False)).all():
        last = Message.query.filter(
            ((Message.sender_id == admin_id) & (Message.receiver_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.receiver_id == admin_id))
        ).order_by(Message.id.desc()).first()
        if last and last.sender_id == user.id:
            pending += 1
    return pending


# Admin Dashboard
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """Ce qui attend l'administrateur, et rien d'autre en premier plan.

    L'ancienne version affichait quatre compteurs (articles, comptes,
    commentaires, bannieres). Ces nombres ne changent pratiquement jamais et
    n'indiquent aucune action : ils sont relegues en bas de page. Le haut
    repond a la seule question utile — est-ce que quelque chose attend ?
    """
    from app.models import BlockedUploadEvent

    now = datetime.utcnow()

    pending_replies = _conversations_awaiting_reply(current_user.id)
    unread_contact = ContactMessage.query.filter_by(is_read=False).count()
    drafts = Post.query.filter(Post.is_draft.is_(True), Post.is_published.is_(False),
                              Post.scheduled_date.is_(None)).count()
    scheduled = Post.query.filter(
        Post.is_published.is_(False),
        Post.scheduled_date.isnot(None),
        Post.scheduled_date > now,
    ).count()
    recent_blocks = BlockedUploadEvent.query.filter(
        BlockedUploadEvent.created_at > now - timedelta(days=30)
    ).count()

    # Chaque entree n'apparait que si son compte est non nul : une liste de
    # zeros n'est pas une liste de taches.
    waiting = [
        {'count': pending_replies,
         'label': 'conversation awaiting a reply',
         'plural': 'conversations awaiting a reply',
         'url': url_for('admin_chat'), 'urgent': True},
        {'count': unread_contact,
         'label': 'unread contact message',
         'plural': 'unread contact messages',
         'url': url_for('manage_posts'), 'urgent': True},
        {'count': recent_blocks,
         'label': 'blocked upload this month',
         'plural': 'blocked uploads this month',
         'url': url_for('admin_moderation'), 'urgent': True},
        {'count': drafts,
         'label': 'draft left open',
         'plural': 'drafts left open',
         'url': url_for('manage_posts'), 'urgent': False},
        {'count': scheduled,
         'label': 'post scheduled to go out',
         'plural': 'posts scheduled to go out',
         'url': url_for('manage_posts'), 'urgent': False},
    ]
    waiting = [item for item in waiting if item['count']]

    latest_post = Post.query.order_by(Post.date_posted.desc()).first()
    latest_comment = Comment.query.order_by(Comment.date_posted.desc()).first()

    return render_template(
        'admin_dashboard.html',
        waiting=waiting,
        total_posts=Post.query.filter_by(is_published=True).count(),
        total_users=User.query.filter(User.is_admin.is_(False)).count(),
        total_comments=Comment.query.count(),
        total_banners=Banner.query.filter_by(is_active=True).count(),
        latest_post=latest_post,
        latest_comment=latest_comment,
        now=now,
    )


# Donate Page
@app.route('/donate', methods=['GET', 'POST'])
def donate():
    form = EmptyForm()

    if request.method == 'POST':
        # Donations are made with the external swap service; recording an amount
        # here is unverified, so only an admin may do it (anyone could
        # otherwise forge the "top donor" list).
        if not (current_user.is_authenticated and current_user.is_admin) \
                or not form.validate_on_submit():
            abort(403)
        try:
            amount = float((request.form.get('amount') or '0').strip())
        except ValueError:
            amount = None
        if amount is None or not math.isfinite(amount) or not 0 < amount <= 100000:
            flash('Please enter a valid amount.', 'danger')
            return redirect(url_for('donate'))
        # Only valid entries count: a typo must not consume the quota.
        if _action_rate_limited('donate', 3, 3600):
            flash('Too many submissions. Please try again later.', 'danger')
            return redirect(url_for('donate'))
        db.session.add(Donor(name='Anonymous', amount=round(amount, 4)))
        db.session.commit()
        flash("Thank you for your donation!", "success")
        return redirect(url_for('donate'))

    top_donors = Donor.query.order_by(Donor.amount.desc()).limit(5).all()
    return render_template('donate.html', form=form, top_donors=top_donors)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = EmptyForm()

    if request.method == 'POST':
        if _action_rate_limited('chat_submit', max_calls=30, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('chat'))
        message_content = request.form.get('message', '').strip()
        file = request.files.get('file')

        # Handle file uploads
        if file and file.filename:
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                max_bytes=MAX_UPLOAD_BYTES
            )
            try:
                file_path, file_type = _store_upload(file, 'chat') if is_valid else (None, None)
            except UploadRefused as refused:
                flash(str(refused), 'danger')
                return redirect(url_for('index'))
            if file_path:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=_get_admin_user_id(),  # actual admin
                    file_path=file_path,
                    file_type=file_type
                )
                message.set_encrypted_content(message_content)
                db.session.add(message)
                db.session.commit()
                publish_mobile_event('new_message', serialize_chat_message(message))
                _notify_admins_new_message(message)
                flash("File sent!", "success")
            else:
                flash(f"File upload failed: {validation_msg or 'invalid file'}", "danger")

        elif message_content:
            if len(message_content) > 5000:
                flash("Message too long (max 5000 characters).", "danger")
                return redirect(url_for('chat'))
            # Save text message (encrypted at rest)
            message = Message(
                sender_id=current_user.id,
                receiver_id=_get_admin_user_id(),  # actual admin
            )
            message.set_encrypted_content(message_content)
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            _notify_admins_new_message(message)
            flash("Message sent!", "success")

        return redirect(url_for('chat'))

    # SECURITY: only this user's own conversation with the admins
    # (previously every logged-in user saw ALL private messages).
    messages = _user_conversation_query(current_user.id).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', form=form, messages=messages)


@socketio.on('connect')
def socket_connect(auth=None):
    # Only authenticated users may open a socket; each joins a private room.
    if not current_user.is_authenticated:
        return False
    join_room(_user_room(current_user.id))


@socketio.on('message')
def handle_message(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    if not isinstance(data, dict):
        return
    msg = str(data.get('msg', '')).strip()
    if not msg or len(msg) > 5000:
        return
    # Same counter as the /chat route.
    if _action_rate_limited('chat_submit', max_calls=30, window_seconds=300):
        return
    message = Message(sender_id=current_user.id, receiver_id=_get_admin_user_id())
    message.set_encrypted_content(msg)
    db.session.add(message)
    db.session.commit()
    publish_mobile_event('new_message', serialize_chat_message(message))
    _notify_admins_new_message(message)
    # Acknowledge to the sender only (never broadcast private messages).
    emit('message', {'id': message.id, 'msg': msg}, to=_user_room(current_user.id))


@app.route('/admin/chat')
@admin_required
def admin_chat():
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get all messages
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    
    return render_template('admin_chat.html', messages=messages, users=users)


@app.route('/admin/chat/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_chat_user(user_id):
    # Get target user
    target_user = db.get_or_404(User, user_id)

    # Wait-mode endpoint: block shortly and refresh only when new message is available
    wait_mode = request.args.get('wait') == '1'
    last_seen_id = request.args.get('last_seen_id', type=int, default=0)
    if request.method == 'GET' and wait_mode:
        has_new_message = wait_for_conversation_message(current_user.id, user_id, last_seen_id, timeout_seconds=25)
        if has_new_message:
            return redirect(url_for('admin_chat_user', user_id=user_id))
        return redirect(url_for('admin_chat_user', user_id=user_id, wait=1, last_seen_id=last_seen_id))
    
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get messages between admin and this user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Handle message sending
    if request.method == 'POST':
        if _action_rate_limited('admin_chat_submit', max_calls=60, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('admin_chat_user', user_id=user_id))
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
        
        if content or file:
            message = Message(
                sender_id=current_user.id,
                receiver_id=user_id
            )
            
            # Handle text content
            if content:
                message.set_encrypted_content(content)
            else:
                message.set_encrypted_content("")
            
            # Handle file upload
            if file and file.filename:
                is_valid, validation_msg = _validate_uploaded_file(
                    file,
                    allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                    max_bytes=MAX_UPLOAD_BYTES
                )
                try:
                    file_path, file_type = _store_upload(file, 'chat') if is_valid else (None, None)
                except UploadRefused as refused:
                    flash(str(refused), 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
                if file_path:
                    message.file_path = file_path
                    message.file_type = file_type
                else:
                    flash(f'File upload blocked: {validation_msg or "invalid file"}', 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
            
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            
            # Real-time ping to the recipient only (content stays server-side)
            socketio.emit('new_message', {'message_id': message.id}, to=_user_room(user_id))
            
            flash('Message sent!', 'success')
            return redirect(url_for('admin_chat_user', user_id=user_id))

    latest_message_id = messages[-1].id if messages else 0

    return render_template('admin_chat_user.html',
                         messages=messages,
                         users=users,
                         target_user=target_user,
                         latest_message_id=latest_message_id)


def _attachment_message(filename):
    """The Message whose attachment is `filename`, if any (current "uploads/<name>"
    form or older bare file name)."""
    base = os.path.basename(filename)
    return Message.query.filter(
        (Message.file_path == base) | (Message.file_path.like(f'%/{base}'))
    ).first()


def _can_access_upload(filename):
    """Profile pictures: owner + admins. Chat attachments: sender, receiver
    and admins. Anything else (orphans, unknown, anonymous) is denied."""
    if not current_user.is_authenticated:
        return False
    candidates = [f"uploads/{filename}", os.path.join('uploads', filename), filename]
    owner = User.query.filter(User.profile_picture.in_(candidates)).first()
    if owner:
        return current_user.is_admin or current_user.id == owner.id
    message = _attachment_message(filename)
    if not message:
        return False
    return current_user.is_admin or current_user.id in (message.sender_id, message.receiver_id)


def _send_upload(filename):
    if filename != secure_filename(filename) or not _can_access_upload(filename):
        abort(404)
    upload_dir = _uploads_root()
    display_name = upload_display_name(filename)
    is_image = _file_ext(display_name) in IMAGE_EXTENSIONS
    if filename.endswith(ENCRYPTED_SUFFIX):
        try:
            data = read_upload_bytes(f"{UPLOAD_FOLDER}/{filename}")
        except (OSError, ValueError, InvalidToken):
            abort(404)
        mimetype = mimetypes.guess_type(display_name)[0] or 'application/octet-stream'
        response = send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=not is_image,
                             download_name=display_name)
    else:
        # legacy plaintext file (run `flask encrypt-legacy` to encrypt it)
        response = send_from_directory(upload_dir, filename, as_attachment=not is_image)
    # Never let an uploaded file run script in our origin.
    response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Route to serve uploaded files (access controlled)."""
    return _send_upload(filename)

@app.route('/static/uploads/<filename>')
def static_uploaded_file(filename):
    """Legacy path, same access control."""
    return _send_upload(filename)


@app.route('/manage_posts', methods=['GET', 'POST'])
@admin_required
def manage_posts():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        scheduled_date = form.scheduled_date.data
        is_published = bool(form.is_published.data)
        post = Post(
            title=title,
            content=content,
            author_id=current_user.id,
            scheduled_date=scheduled_date,
            is_published=is_published,
            # neither "publish now" nor a date => stays a private draft
            is_draft=not is_published and not scheduled_date
        )
        apply_post_taxonomy(post, form.category.data, form.tags.data)
        db.session.add(post)
        db.session.commit()
        
        # Add experience points for creating a post
        current_user.add_experience(10)
        
        # Check and award badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('manage_posts'))
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('manage_posts.html', form=form, posts=posts)

@app.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    users = User.query.all()
    form = EmptyForm()
    return render_template('manage_users.html', users=users, form=form)


@app.route('/manage_comments', methods=['GET', 'POST'])
@admin_required
def manage_comments():
    current_filter = request.args.get('filter', 'all')
    query = Comment.query
    if current_filter == 'recent':
        query = query.filter(Comment.date_posted >= datetime.utcnow() - timedelta(days=7))
    elif current_filter == 'popular':
        query = query.filter(Comment.likes_count >= 5)
    else:
        current_filter = 'all'
    comments = query.order_by(Comment.date_posted.desc()).all()
    form = EmptyForm()
    return render_template('manage_comments.html', comments=comments, form=form, current_filter=current_filter)

@app.route('/site_statistics')
@admin_required
def site_statistics():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    # User with the most posts
    most_active_user = db.session.query(User.username, db.func.count(Post.id).label('post_count'))\
        .join(Post).group_by(User.id).order_by(db.func.count(Post.id).desc()).first()

    return render_template('site_statistics.html',
                           total_users=total_users,
                           total_admins=total_admins,
                           total_posts=total_posts,
                           total_comments=total_comments,
                           most_active_user=most_active_user)

@app.route('/manage_banners', methods=['GET', 'POST'])
@admin_required
def manage_banners():
    form = BannerForm()
    banners = Banner.query.all()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        image_url = form.image_url.data
        link_url = form.link_url.data
        position = form.position.data
        is_active = form.is_active.data
        
        banner = Banner(
            title=title,
            content=content,
            image_url=image_url,
            link_url=link_url,
            position=position,
            is_active=is_active
        )
        
        db.session.add(banner)
        db.session.commit()
        flash('Banner created successfully!', 'success')
        return redirect(url_for('manage_banners'))

    return render_template('manage_banners.html', banners=banners, form=form, delete_form=EmptyForm())

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if _action_rate_limited('upload_file_submit', max_calls=12, window_seconds=300):
        flash('Too many uploads. Please wait a bit.', 'danger')
        return redirect(url_for('chat'))
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('chat'))

    file = request.files['file']

    if file.filename == '':
        flash('No file uploaded!', 'danger')
        return redirect(url_for('chat'))

    is_valid, validation_msg = _validate_uploaded_file(
        file,
        allowed_exts=UPLOAD_FILE_ALLOWED_EXTENSIONS,
        max_bytes=MAX_UPLOAD_BYTES,
        image_only=True
    )
    if not is_valid:
        flash(f'Invalid file type! {validation_msg}', 'danger')
        return redirect(url_for('chat'))

    # Random name + full metadata strip, then attach it to the user's chat
    # (the old code kept the user's filename: files could overwrite each other).
    try:
        file_path, file_type = _store_upload(file, 'chat')
    except UploadRefused as refused:
        flash(str(refused), 'danger')
        return redirect(url_for('index'))
    if not file_path:
        flash('Invalid image file!', 'danger')
        return redirect(url_for('chat'))
    message = Message(sender_id=current_user.id, receiver_id=_get_admin_user_id(),
                      file_path=file_path, file_type=file_type)
    message.set_encrypted_content('')
    db.session.add(message)
    db.session.commit()
    publish_mobile_event('new_message', serialize_chat_message(message))
    _notify_admins_new_message(message)

    flash('Image uploaded (metadata removed).', 'success')
    return redirect(url_for('chat'))

@app.route('/manage_pages', methods=['GET', 'POST'])
@admin_required
def manage_pages():
    pages = StaticPage.query.all()
    form = StaticPageForm()

    if form.validate_on_submit():
        slug = _unique_page_slug(form.slug.data or form.title.data)
        page = StaticPage(title=form.title.data, slug=slug, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('manage_pages'))

    return render_template('manage_pages.html', pages=pages, form=form)




@app.route('/demote_user/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    user = db.get_or_404(User, user_id)

    if user.is_admin:
        if User.query.filter_by(is_admin=True).count() <= 1:
            flash('Cannot demote the last admin.', 'danger')
            return redirect(url_for('manage_users'))
        user.is_admin = False
        # A role change must take effect on sessions that are already open.
        user.rotate_session_token()
        db.session.commit()
        security_alert(f"@{current_user.username} demoted admin @{user.username}")
        flash(f'User {user.username} has been demoted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_page', methods=['GET', 'POST'])
@admin_required
def create_page():
    form = StaticPageForm()

    if form.validate_on_submit():
        # slug is NOT NULL + unique: the old code crashed here (500)
        slug = _unique_page_slug(form.slug.data or form.title.data)
        page = StaticPage(title=form.title.data, slug=slug, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash('New page created!', 'success')
        return redirect(url_for('manage_pages'))

    return render_template('create_page.html', form=form)


def _unique_page_slug(text, exclude_id=None):
    base = re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')[:90] or 'page'
    slug, n = base, 2
    while True:
        existing = StaticPage.query.filter_by(slug=slug).first()
        if not existing or existing.id == exclude_id:
            return slug
        slug = f"{base}-{n}"
        n += 1


@app.route('/page/<slug>')
def view_page(slug):
    page = StaticPage.query.filter_by(slug=slug).first_or_404()
    return render_template('view_page.html', page=page)


@app.route('/edit_page/<page_name>', methods=['GET', 'POST'])
@admin_required
def edit_page(page_name):
    page = StaticPage.query.filter_by(slug=page_name).first_or_404()
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()[:100]
        content = request.form.get('content') or ''
        if not title or not content.strip():
            flash('Title and content are required.', 'danger')
            return redirect(url_for('edit_page', page_name=page.slug))
        page.title = title
        page.content = content
        page.date_modified = datetime.utcnow()
        db.session.commit()
        flash('Page updated!', 'success')
        return redirect(url_for('manage_pages'))
    return render_template('edit_page.html', page=page)


@app.route('/delete_page/<int:page_id>', methods=['POST'])
@admin_required
def delete_page(page_id):
    page = db.get_or_404(StaticPage, page_id)
    db.session.delete(page)
    db.session.commit()
    flash('Page deleted.', 'success')
    return redirect(url_for('manage_pages'))


@app.route('/edit_banner/<int:banner_id>', methods=['GET', 'POST'])
@admin_required
def edit_banner(banner_id):
    banner = db.get_or_404(Banner, banner_id)
    form = BannerForm(obj=banner)
    if form.validate_on_submit():
        form.populate_obj(banner)
        db.session.commit()
        flash('Banner updated!', 'success')
        return redirect(url_for('manage_banners'))
    return render_template('manage_banners.html', banners=Banner.query.all(), form=form,
                           delete_form=EmptyForm(),
                           form_action=url_for('edit_banner', banner_id=banner.id))


@app.route('/delete_banner/<int:banner_id>', methods=['POST'])
@admin_required
def delete_banner(banner_id):
    banner = db.get_or_404(Banner, banner_id)
    db.session.delete(banner)
    db.session.commit()
    flash('Banner deleted.', 'success')
    return redirect(url_for('manage_banners'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    try:
        _delete_post_and_children(post)
    except IntegrityError:
        flash('This post could not be deleted.', 'danger')
        return redirect(url_for('manage_posts'))
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_posts'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = db.get_or_404(Post, post_id)
    form = PostForm(obj=post)
    if request.method == 'GET':
        form.tags.data = ', '.join(t.name for t in post.tags)

    if form.validate_on_submit():
        last_version = db.session.query(db.func.max(Revision.version)).filter_by(post_id=post.id).scalar() or 0
        db.session.add(Revision(post_id=post.id, content=post.content, version=last_version + 1))
        post.title = form.title.data
        post.content = form.content.data
        apply_post_taxonomy(post, form.category.data, form.tags.data)
        post.is_published = bool(form.is_published.data)
        post.scheduled_date = form.scheduled_date.data
        post.is_draft = not post.is_published and not post.scheduled_date
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete an account and everything attached to it.

    Comments stay (shown as "[deleted]"), posts go to the admin who deletes.
    Chat messages are permanently erased: the operation therefore requires
    `purge_messages=1` as soon as there are some.
    """
    user = db.get_or_404(User, user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own account from here.', 'danger')
        return redirect(url_for('manage_users'))
    if user.is_admin:
        flash('Demote this administrator before deleting the account.', 'danger')
        return redirect(url_for('manage_users'))

    messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)).count()
    if messages and request.form.get('purge_messages') != '1':
        flash(f'{user.username} has {messages} chat message(s). Deleting the '
              'account erases them permanently: tick "also delete messages" and '
              'confirm.', 'danger')
        return redirect(url_for('manage_users'))

    username = user.username
    try:
        _delete_user_and_data(user, new_post_owner_id=current_user.id,
                              uploads_root=_uploads_root())
    except IntegrityError:
        flash('This account could not be deleted.', 'danger')
        return redirect(url_for('manage_users'))
    security_alert(f"@{current_user.username} deleted user @{username}")
    flash(f'User {username} deleted.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/promote_user/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = db.get_or_404(User, user_id)
    user.is_admin = True
    user.rotate_session_token()
    db.session.commit()
    security_alert(f"@{current_user.username} promoted @{user.username} to ADMIN")
    flash(f"{user.username} has been promoted to admin.", "success")
    return redirect(url_for('manage_users'))






@app.route("/delete_comment/<int:comment_id>/<int:post_id>", methods=["POST"]) 
@rate_limit('delete_comment', max_calls=15, window_seconds=300)
@login_required
def delete_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)

    # Admin can delete everything, otherwise user can only delete their own comments
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    Like.query.filter_by(comment_id=comment.id).delete(synchronize_session=False)
    if comment.replies:
        # keep the thread structure, erase the content
        comment.deleted = True
        comment.content = '[deleted]'
    else:
        Notification.query.filter_by(related_comment_id=comment.id).delete(synchronize_session=False)
        db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully!", "success")
    return redirect(url_for("post_detail", post_id=post_id))



@app.route("/posts")
def post_list():
    posts = _published_posts_query().order_by(Post.date_posted.desc()).all()
    return render_template("post_list.html", posts=posts)

@app.route("/reply_to_comment/<int:post_id>/<int:comment_id>", methods=["POST"])
@rate_limit('reply_to_comment', max_calls=10, window_seconds=300)
@login_required
def reply_to_comment(post_id, comment_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    parent_comment = db.get_or_404(Comment, comment_id)
    if parent_comment.post_id != post.id or parent_comment.deleted:
        abort(404)

    form = CommentForm()

    if form.validate_on_submit():
        reply = Comment(
            content=form.content.data.strip(),  # plain text + BBCode, escaped at render
            content_format='bbcode',
            author=current_user,
            post_id=post.id,
            parent_id=parent_comment.id
        )
        db.session.add(reply)
        db.session.commit()
        
        # Add experience points for reply
        current_user.add_experience(2)
        
        # Create notification for parent comment author
        if parent_comment.author_id and parent_comment.author_id != current_user.id:
            notification = Notification(
                user_id=parent_comment.author_id,
                type='reply',
                title='New reply!',
                message='Someone replied to your comment',
                related_post_id=post.id,
                related_comment_id=reply.id
            )
            db.session.add(notification)
            
            _notify_user(parent_comment.author_id, {
                'type': 'reply',
                'title': 'New reply!',
                'message': 'Someone replied to your comment',
            })
        
        # Check and award badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash("Your reply has been added!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    if form.form_ts.errors or form.website.errors:
        _flash_antispam_errors(form)
    else:
        flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
    return redirect(url_for("post_detail", post_id=post.id))


@app.route("/edit_comment/<int:comment_id>/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)
    post = db.get_or_404(Post, comment.post_id)

    # Admins can edit every comment, users only their own
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access
    if comment.deleted:
        abort(404)

    form = CommentForm()
    if form.validate_on_submit():
        if _action_rate_limited('edit_comment_submit', max_calls=20, window_seconds=300):
            flash('Too many edits. Please wait.', 'danger')
            return redirect(url_for('post_detail', post_id=post.id))
        # Plain text + BBCode: an old (HTML) row becomes clean text as soon as
        # it is edited.
        comment.content = form.content.data.strip()
        comment.content_format = 'bbcode'
        db.session.commit()
        flash("Comment updated!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    # Pre-fill: an old HTML row is shown as text (in memory only, the database
    # row is not touched before the save).
    form.content.data = (comment.content if comment.content_format == 'bbcode'
                         else html_to_text(comment.content))
    return render_template("edit_comment.html", title="Edit Comment", form=form, post=post, comment=comment)


def _revoke_like_reward(author, points, related_post_id=None, related_comment_id=None):
    """Cancel the effect of a removed like: XP and unread notification.

    Without this, like/unlike in a loop gave unlimited XP and one notification
    per cycle. The level is never lowered.
    """
    if author is None:
        return
    author.experience_points = max(0, (author.experience_points or 0) - points)
    query = Notification.query.filter_by(user_id=author.id, type='like', is_read=False)
    if related_comment_id is not None:
        query = query.filter_by(related_comment_id=related_comment_id)
    else:
        query = query.filter_by(related_post_id=related_post_id, related_comment_id=None)
    latest = query.order_by(Notification.id.desc()).first()
    if latest is not None:
        db.session.delete(latest)


# Likes
@app.route('/like_post/<int:post_id>', methods=['POST'])
@rate_limit('like_post', max_calls=20, window_seconds=300)
@login_required
def like_post(post_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    
    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        post.likes_count = max(0, (post.likes_count or 0) - 1)
        if post.author_id != current_user.id:
            _revoke_like_reward(post.author, 5, related_post_id=post_id)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        post.likes_count = (post.likes_count or 0) + 1
        
        # Add experience points to post author
        if post.author_id != current_user.id:
            post.author.add_experience(5)
            
            # Create notification for author
            notification = Notification(
                user_id=post.author_id,
                type='like',
                title='New like!',
                message=f'Someone liked your article "{post.title}"',
                related_post_id=post_id
            )
            db.session.add(notification)
            
            _notify_user(post.author_id, {
                'type': 'like',
                'title': 'New like!',
                'message': f'Someone liked your article "{post.title}"',
            })
        
        flash('Article liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@rate_limit('like_comment', max_calls=20, window_seconds=300)
@login_required
def like_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    _require_visible_post(comment.post)
    
    # Check if user already liked this comment
    existing_like = Like.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        comment.likes_count = max(0, (comment.likes_count or 0) - 1)
        if comment.author_id and comment.author_id != current_user.id:
            _revoke_like_reward(comment.author, 2, related_comment_id=comment_id)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        comment.likes_count = (comment.likes_count or 0) + 1
        
        # Add experience points to comment author
        if comment.author_id and comment.author_id != current_user.id:
            comment.author.add_experience(2)
            
            # Notify the author
            notification = Notification(
                user_id=comment.author_id,
                type='like',
                title='Comment liked!',
                message='Someone liked your comment',
                related_comment_id=comment_id,
                related_post_id=comment.post_id
            )
            db.session.add(notification)
            
            _notify_user(comment.author_id, {
                'type': 'like',
                'title': 'Comment liked!',
                'message': 'Someone liked your comment',
            })
        
        flash('Comment liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=comment.post_id))


# Notifications
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).all()
    form = EmptyForm()
    return render_template('notifications.html', notifications=user_notifications, form=form)


@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = db.get_or_404(Notification, notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False)\
        .update({'is_read': True})
    db.session.commit()
    flash('All notifications were marked as read!', 'success')
    return redirect(url_for('notifications'))


# Badges and levels
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    user = db.get_or_404(User, user_id)
    user_posts = Post.query.filter_by(author_id=user_id, is_published=True).order_by(Post.date_posted.desc()).limit(5).all()
    user_comments = Comment.query.filter_by(author_id=user_id).order_by(Comment.date_posted.desc()).limit(5).all()
    
    # Statistics
    total_posts = Post.query.filter_by(author_id=user_id, is_published=True).count()
    total_comments = Comment.query.filter_by(author_id=user_id).count()
    total_likes_received = db.session.query(db.func.sum(Post.likes_count))\
        .filter(Post.author_id == user_id).scalar() or 0
    
    return render_template('user_profile.html', 
                         user=user, 
                         user_posts=user_posts,
                         user_comments=user_comments,
                         total_posts=total_posts,
                         total_comments=total_comments,
                         total_likes_received=total_likes_received)


# Create the default badges (run once)
@app.route('/init_badges')
@admin_required
def init_badges():
    create_default_badges()
    flash('Default badges created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# Edit profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(original_username=current_user.username)
    
    if form.validate_on_submit():
        if _action_rate_limited('edit_profile_submit', max_calls=10, window_seconds=300):
            flash('Too many updates. Please wait.', 'danger')
            return redirect(url_for('edit_profile'))
        # Update the username
        current_user.username = form.username.data
        
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=PROFILE_ALLOWED_EXTENSIONS,
                max_bytes=min(MAX_UPLOAD_BYTES, 3 * 1024 * 1024),
                image_only=True
            )
            file_path = None
            if is_valid:
                try:
                    file_path, _ = _store_upload(file, 'profile')
                except UploadRefused as refused:
                    flash(str(refused), 'danger')
                    return redirect(url_for('index'))
            if file_path:
                # Remove old photo if it exists (only inside the uploads folder)
                _remove_upload_file(current_user.profile_picture)
                current_user.profile_picture = file_path
            else:
                validation_msg = validation_msg or 'invalid image'
                flash(f'Profile picture rejected: {validation_msg}', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    # Pre-fill form with current data
    form.username.data = current_user.username
    
    return render_template('edit_profile.html', form=form)


# ─────────────────────────────────────────────────────────────────
#  TOTP / 2FA routes
# ─────────────────────────────────────────────────────────────────

def _totp_qr_data_uri(secret: str, username: str) -> str:
    """Return a data: URI PNG of the provisioning QR code (no file on disk)."""
    import qrcode
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='depressedyoungman'
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode('ascii')
    return f'data:image/png;base64,{b64}'


@app.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    """Generate a new TOTP secret and show the QR code.
    On POST with a valid 6-digit code, activate 2FA for the user.
    """
    if current_user.totp_enabled:
        flash('Two-factor authentication is already active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPSetupForm()

    # Generate (or reuse pending) secret stored in session
    if 'totp_pending_secret' not in session:
        session['totp_pending_secret'] = pyotp.random_base32()

    pending_secret = session['totp_pending_secret']

    if form.validate_on_submit():
        if hit_rate_limit(f"totp_setup_fail:{current_user.id}", 10, 300, record=False):
            flash('Too many attempts. Please wait a few minutes.', 'danger')
            return redirect(url_for('totp_setup'))
        user = current_user._get_current_object()
        if _verify_totp_once(user, form.code.data, secret=pending_secret):
            # Secret encrypted at rest; the accepted step is remembered (no replay).
            _store_totp_secret(user, pending_secret)
            user.totp_enabled = True
            codes = generate_recovery_codes(user)
            # Sessions and "remember" cookies already issued no longer match;
            # the current browser is re-opened with the new version.
            invalidate_other_sessions(user)  # commits
            session.pop('totp_pending_secret', None)
            login_user(user)
            security_alert(f"2FA enabled by @{current_user.username}")
            flash('Two-factor authentication has been enabled!', 'success')
            # Shown once, never stored in clear
            return render_template('recovery_codes.html', codes=codes)
        else:
            hit_rate_limit(f"totp_setup_fail:{current_user.id}", 10, 300)
            flash('Invalid code. Please try again.', 'danger')

    qr_uri = _totp_qr_data_uri(pending_secret, current_user.username)
    return render_template(
        'totp_setup.html',
        form=form,
        qr_uri=qr_uri,
        totp_secret=pending_secret
    )


@app.route('/totp/disable', methods=['GET', 'POST'])
@login_required
def totp_disable():
    """Disable 2FA after confirming current password + a valid TOTP code."""
    if not current_user.totp_enabled:
        flash('Two-factor authentication is not currently active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPDisableForm()

    if form.validate_on_submit():
        fail_key = f"totp_disable_fail:{current_user.id}"
        if hit_rate_limit(fail_key, 5, 900, record=False):
            flash('Too many failed attempts. Please wait 15 minutes.', 'danger')
            return render_template('totp_disable.html', form=form)
        if not _check_user_password(current_user, form.password.data):
            hit_rate_limit(fail_key, 5, 900)
            flash('Incorrect password.', 'danger')
            return render_template('totp_disable.html', form=form)

        if not verify_second_factor(current_user, form.code.data):
            hit_rate_limit(fail_key, 5, 900)
            flash('Invalid authentication code.', 'danger')
            return render_template('totp_disable.html', form=form)

        user = current_user._get_current_object()
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_last_counter = None
        user.recovery_codes = None
        invalidate_other_sessions(user)  # commits
        login_user(user)
        security_alert(f"2FA DISABLED by @{user.username}")
        flash('Two-factor authentication has been disabled.', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))

    return render_template('totp_disable.html', form=form)



# ─────────────────────────────────────────────────────────────────
#  Account security: password, sessions, recovery codes, export, deletion
# ─────────────────────────────────────────────────────────────────

def _reauthenticate(form):
    """Password (+ 2FA code when enabled) check before a sensitive action.
    Returns True or flashes the reason. Rate limited per account."""
    fail_key = f"reauth_fail:{current_user.id}"
    if hit_rate_limit(fail_key, 5, 900, record=False):
        flash('Too many failed attempts. Please wait 15 minutes.', 'danger')
        return False
    if not _check_user_password(current_user, form.password.data):
        hit_rate_limit(fail_key, 5, 900)
        flash('Incorrect password.', 'danger')
        return False
    if current_user.totp_enabled and not verify_second_factor(current_user, form.code.data):
        hit_rate_limit(fail_key, 5, 900)
        flash('A valid 2FA code (or recovery code) is required.', 'danger')
        return False
    return True


def _account_security_page(**forms):
    defaults = dict(password_form=ChangePasswordForm(), recovery_form=ReauthForm(prefix='rc'),
                    export_form=ReauthForm(prefix='ex'), delete_form=DeleteAccountForm(prefix='del'),
                    sessions_form=EmptyForm(prefix='ss'))
    defaults.update(forms)
    return render_template('account_security.html',
                           recovery_left=recovery_codes_left(current_user), **defaults)


@app.route('/account/security')
@login_required
def account_security():
    return _account_security_page()


@app.route('/account/password', methods=['GET', 'POST'])
@login_required
@rate_limit('change_password', max_calls=10, window_seconds=600)
def change_password():
    """Change the password.

    Also the mandatory exit when `must_change_password` is set: the deployment
    script generates a random password, and this page is what turns "it must be
    changed" into an actual constraint.
    """
    form = ChangePasswordForm()
    forced = bool(current_user.must_change_password)
    if request.method == 'GET' or not form.validate_on_submit():
        return render_template('change_password.html', form=form, forced=forced)
    if hit_rate_limit(f"reauth_fail:{current_user.id}", 5, 900, record=False):
        flash('Too many failed attempts. Please wait 15 minutes.', 'danger')
        return redirect(url_for('account_security'))
    if not _check_user_password(current_user, form.current_password.data):
        hit_rate_limit(f"reauth_fail:{current_user.id}", 5, 900)
        flash('Incorrect current password.', 'danger')
        return render_template('change_password.html', form=form, forced=forced)
    current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
    current_user.must_change_password = False
    user = current_user._get_current_object()
    invalidate_other_sessions(user)  # commits; every other session is now logged out
    _start_fresh_session()
    login_user(user)
    security_alert(f"password changed by @{user.username}")
    flash('Password changed. You were logged out of every other device.', 'success')
    return redirect(url_for('account_security'))


@app.route('/account/logout-everywhere', methods=['POST'])
@login_required
def logout_everywhere():
    form = EmptyForm(prefix='ss')
    if not form.validate_on_submit():
        abort(400)
    user = current_user._get_current_object()
    invalidate_other_sessions(user)
    _start_fresh_session()
    login_user(user)
    flash('You were logged out of every other device and browser.', 'success')
    return redirect(url_for('account_security'))


@app.route('/account/recovery-codes', methods=['POST'])
@login_required
def regenerate_recovery_codes():
    form = ReauthForm(prefix='rc')
    if not current_user.totp_enabled:
        flash('Enable 2FA first.', 'info')
        return redirect(url_for('account_security'))
    if not form.validate_on_submit() or not _reauthenticate(form):
        return _account_security_page(recovery_form=form)
    codes = generate_recovery_codes(current_user)
    db.session.commit()
    security_alert(f"new 2FA recovery codes generated by @{current_user.username}")
    return render_template('recovery_codes.html', codes=codes)


@app.route('/account/export', methods=['POST'])
@login_required
def export_account_data():
    form = ReauthForm(prefix='ex')
    if not form.validate_on_submit() or not _reauthenticate(form):
        return _account_security_page(export_form=form)
    if _action_rate_limited('account_export', max_calls=5, window_seconds=3600):
        flash('Too many exports. Please wait.', 'danger')
        return redirect(url_for('account_security'))
    payload = json.dumps(export_user_data(current_user), indent=2, ensure_ascii=False)
    response = app.response_class(payload, mimetype='application/json')
    response.headers['Content-Disposition'] = f'attachment; filename="my-data-{current_user.id}.json"'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/account/delete', methods=['POST'])
@login_required
def delete_own_account():
    form = DeleteAccountForm(prefix='del')
    if not form.validate_on_submit() or not _reauthenticate(form):
        return _account_security_page(delete_form=form)
    user = current_user._get_current_object()
    other_admin = User.query.filter(User.is_admin.is_(True), User.id != user.id).order_by(User.id.asc()).first()
    if user.is_admin and not other_admin:
        flash('You are the last admin: promote another admin before deleting your account.', 'danger')
        return redirect(url_for('account_security'))
    if other_admin:
        _delete_user_and_data(user, new_post_owner_id=other_admin.id)
    else:
        for post in Post.query.filter_by(author_id=user.id).all():
            _delete_post_and_children(post)
        _delete_user_and_data(user, new_post_owner_id=None)
    security_alert(f"account @{user.username} deleted by its owner")
    logout_user()
    session.clear()
    flash('Your account and your personal data were deleted.', 'success')
    return redirect(url_for('index'))



# ─────────────────────────────────────────────────────────────────
#  Discovery: categories, tags, search, RSS
# ─────────────────────────────────────────────────────────────────

def _post_listing(posts, heading, empty_message=None, query=None):
    return render_template('post_list.html', posts=posts, heading=heading,
                           empty_message=empty_message or get_text('posts.none_found'),
                           query=query)


@app.route('/tag/<slug>')
def posts_by_tag(slug):
    tag = Tag.query.filter_by(slug=slug).first_or_404()
    posts = _published_posts_query().filter(Post.tags.any(Tag.id == tag.id)) \
        .order_by(Post.date_posted.desc()).all()
    return _post_listing(posts, f"{get_text('posts.tag.heading')}: {tag.name}")


@app.route('/category/<slug>')
def posts_by_category(slug):
    names = [c for (c,) in db.session.query(Post.category).filter(Post.category.isnot(None)).distinct()]
    name = next((c for c in names if slugify(c) == slug), None)
    if not name:
        abort(404)
    posts = _published_posts_query().filter(Post.category == name) \
        .order_by(Post.date_posted.desc()).all()
    return _post_listing(posts, f"{get_text('posts.category.heading')}: {name}")


@app.route('/search')
def search():
    query = (request.args.get('q') or '').strip()[:100]
    heading = get_text('posts.search.heading')
    if not query:
        return _post_listing([], heading, get_text('posts.search.empty'), query='')
    if len(query) < 2:
        return _post_listing([], heading, get_text('posts.search.short'), query=query)
    if _action_rate_limited('search', max_calls=30, window_seconds=60):
        return _post_listing([], heading, get_text('posts.search.limited'), query=query), 429
    escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    pattern = f"%{escaped}%"
    posts = _published_posts_query().filter(
        Post.title.ilike(pattern, escape='\\') | Post.content.ilike(pattern, escape='\\')
        | Post.category.ilike(pattern, escape='\\')
    ).order_by(Post.date_posted.desc()).limit(50).all()
    return _post_listing(posts, f'{heading}: "{query}"', get_text('posts.search.none'), query=query)


@app.route('/feed.xml')
def rss_feed():
    posts = Post.query.filter(Post.is_published.is_(True)).order_by(Post.date_posted.desc()).limit(20).all()
    xml = render_template('feed.xml', posts=posts, base_url=request.url_root.rstrip('/'))
    response = app.response_class(xml, mimetype='application/rss+xml')
    response.headers['Cache-Control'] = 'public, max-age=900'
    return response
