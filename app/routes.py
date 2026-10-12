from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory, session, jsonify, Response, stream_with_context, has_request_context
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, socketio, csrf
from app.utils import parse_bbcode, html_to_text
from app.forms import LoginForm, RegistrationForm, PostForm, CommentForm, EmptyForm, BannerForm, StaticPageForm, ContactForm, ProfileEditForm, TOTPSetupForm, TOTPDisableForm, TOTPVerifyForm, ChangePasswordForm, SiteTextImportForm
from app.models import User, Post, Comment, Revision, Banner, StaticPage, Message, Donor, Like, Notification, Badge, ContactMessage
from app.utils import (rate_limit, role_required, process_image_file, anonymous_client_key,
                       hashed_key, record_failure, too_many_failures, clear_failures,
                       purge_store)
from app.encryption import message_encryption
from functools import wraps
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from flask_socketio import emit
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
import re
import os
import json
import base64
import queue
import time
import uuid
import math
import hmac
import secrets
from threading import Lock
from PIL import Image
import pyotp
import io


# 🔹 Admin-only Route Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Access denied. Only admins can view this page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def _get_admin_user_id() -> int:
    """Return the ID of the first admin user, falling back to user ID 1."""
    admin = User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()
    if admin:
        return admin.id
    return 1


# 🔹 Mobile admin API helpers (Basic Auth + SSE stream)
mobile_event_subscribers = []
mobile_event_lock = Lock()
action_rate_limit_lock = Lock()
action_rate_limit_buckets = {}






































def _action_rate_limited(action_key, max_calls, window_seconds, actor_key=None):
    """Vrai si l'acteur a depasse `max_calls` en `window_seconds`.

    `actor_key` remplace la cle client : utile quand la limite doit porter sur
    un compte cible (2FA en attente) et non sur le visiteur courant.
    """
    now = time.time()
    if actor_key is None:
        actor_key = anonymous_client_key()
        if current_user.is_authenticated:
            actor_key = f"user:{current_user.id}"
    bucket_key = f"{action_key}:{actor_key}"
    with action_rate_limit_lock:
        bucket = action_rate_limit_buckets.get(bucket_key, [])
        bucket = [t for t in bucket if t > now - window_seconds]
        if len(bucket) >= max_calls:
            action_rate_limit_buckets[bucket_key] = bucket
            return True
        bucket.append(now)
        action_rate_limit_buckets[bucket_key] = bucket
        purge_store(action_rate_limit_buckets, now)
    return False






































def parse_basic_auth():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        return None, None

    encoded_credentials = auth_header.split(' ', 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded.split(':', 1)
        return username, password
    except Exception:
        return None, None


# Hash bcrypt d'une valeur aleatoire, utilise pour egaliser le temps de reponse
# quand le compte n'existe pas (login web et API mobile).
_DUMMY_PASSWORD_HASH = bcrypt.generate_password_hash(uuid.uuid4().hex).decode('utf-8')

# Verrouillage de l'API mobile : par pseudo (strict) et par client (large).
# Derriere un service onion tous les clients partagent la meme adresse : la
# limite par client y est donc globale, d'ou un seuil plus haut que par pseudo.
ADMIN_API_USER_MAX_FAILURES = 10
ADMIN_API_CLIENT_MAX_FAILURES = 30
ADMIN_API_LOCKOUT_SECONDS = 900


def _mobile_api_enabled():
    return os.environ.get('MOBILE_API_ENABLED', 'true').strip().lower() \
        not in ('0', 'false', 'no', 'off')


def _admin_api_error(message, status, **headers):
    return jsonify({'error': message}), status, headers


def authenticate_admin_api():
    """Authentifie l'appel Basic Auth. Retourne (utilisateur, None) ou (None, reponse).

    - une verification bcrypt est toujours faite, meme pour un pseudo inconnu
      (sinon le chronometre revele quels pseudos sont admins) ;
    - verrouillage apres des echecs repetes, par pseudo et par client ;
    - les comptes bannis, a changement de mot de passe force ou protegés par
      2FA sont refuses : Basic Auth ne peut pas porter le second facteur.
    """
    username, password = parse_basic_auth()
    if not username or not password:
        return None, _admin_api_error(
            'Authentication required for admin mobile API.', 401,
            **{'WWW-Authenticate': 'Basic realm="Admin Mobile API"'})

    user_key = 'admin_api:user:' + hashed_key(username.lower())
    client_key = 'admin_api:client:' + anonymous_client_key()
    if (too_many_failures(user_key, ADMIN_API_USER_MAX_FAILURES, ADMIN_API_LOCKOUT_SECONDS)
            or too_many_failures(client_key, ADMIN_API_CLIENT_MAX_FAILURES,
                                 ADMIN_API_LOCKOUT_SECONDS)):
        return None, _admin_api_error(
            'Too many failed attempts. Try again later.', 429,
            **{'Retry-After': str(ADMIN_API_LOCKOUT_SECONDS)})

    user = User.query.filter_by(username=username, is_admin=True).first()
    password_ok = bcrypt.check_password_hash(
        user.password if user else _DUMMY_PASSWORD_HASH, password)
    if not user or not password_ok:
        record_failure(user_key)
        record_failure(client_key)
        return None, _admin_api_error(
            'Authentication required for admin mobile API.', 401,
            **{'WWW-Authenticate': 'Basic realm="Admin Mobile API"'})

    if user.is_banned:
        return None, _admin_api_error('This account has been suspended.', 403)
    if user.must_change_password:
        return None, _admin_api_error(
            'Password change required: sign in on the website first.', 403)
    if user.totp_enabled:
        return None, _admin_api_error(
            'This account uses two-factor authentication, which the mobile '
            'API (Basic Auth) cannot satisfy. API access is refused for it.', 403)

    clear_failures(user_key)
    return user, None


def admin_api_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not _mobile_api_enabled():
            abort(404)
        admin_user, error = authenticate_admin_api()
        if error is not None:
            return error

        request.admin_api_user = admin_user
        return f(*args, **kwargs)

    return decorated_function


def serialize_chat_message(message):
    decrypted_content = message.get_decrypted_content() if message.is_encrypted else message.content
    file_url = None
    if message.file_path:
        filename = message.file_path.split('/')[-1]
        if has_request_context():
            file_url = url_for('uploaded_file', filename=filename, _external=True)
        else:
            file_url = f"/uploads/{filename}"

    return {
        'id': message.id,
        'sender_id': message.sender_id,
        'sender_username': message.sender.username if message.sender else None,
        'sender_is_admin': message.sender.is_admin if message.sender else False,
        'receiver_id': message.receiver_id,
        'receiver_username': message.receiver.username if message.receiver else None,
        'content': decrypted_content,
        'file_path': message.file_path,
        'file_url': file_url,
        'file_type': message.file_type,
        'is_encrypted': message.is_encrypted,
        'timestamp': message.timestamp.isoformat() if message.timestamp else None
    }


def publish_mobile_event(event_type, payload):
    event = {
        'type': event_type,
        'payload': payload,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    }

    with mobile_event_lock:
        for subscriber in list(mobile_event_subscribers):
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                continue










def _project_root():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def _uploads_root():
    return os.path.abspath(os.path.join(_project_root(), UPLOAD_FOLDER))


def _absolute_upload_path(stored_path):
    """Chemin absolu d'une piece jointe, borne au dossier uploads/.

    `Message.file_path` ne contient plus que le nom du fichier ; on accepte
    encore les anciennes valeurs relatives ("uploads/x.jpg") et absolues, mais
    tout chemin qui sortirait de uploads/ est rejete.
    """
    if not stored_path:
        return None
    candidate = stored_path if os.path.isabs(stored_path) else os.path.join(_project_root(), UPLOAD_FOLDER, os.path.basename(stored_path))
    candidate = os.path.abspath(candidate)
    root = _uploads_root()
    if os.path.commonpath([candidate, root]) != root:
        return None
    return candidate








































@app.before_request
def enforce_ban():
    """Deconnecte un compte banni des sa requete suivante.

    Sans ce controle, un utilisateur banni resterait actif jusqu'a l'expiration
    de son cookie de session — soit jusqu'a quatre heures.
    """
    if getattr(current_user, 'is_authenticated', False) and getattr(current_user, 'is_banned', False):
        logout_user()
        session.clear()
        if request.endpoint not in ('static', 'login'):
            flash('This account has been suspended.', 'danger')
            return redirect(url_for('login'))


@app.before_request
def enforce_password_change():
    """Renvoie vers le changement de mot de passe tant qu'il est exige.

    Sans ce garde, `must_change_password` ne serait qu'une colonne : le compte
    cree par le script de deploiement resterait utilisable indefiniment avec le
    mot de passe imprime dans un fichier.
    """
    if not getattr(current_user, 'is_authenticated', False):
        return
    if not getattr(current_user, 'must_change_password', False):
        return
    # On laisse passer ce dont la page a besoin, et la deconnexion.
    if request.endpoint in ('change_password', 'logout', 'static', 'static_v'):
        return
    return redirect(url_for('change_password'))


@app.before_request
def publish_due_scheduled_posts():
    """Publie les articles dont la date de programmation est passee.

    Ce hook vivait auparavant dans `telegram_before_request_poll`, qui servait
    surtout a faire tourner le long-polling du bot. Le pont Telegram a ete
    archive (voir archive/telegram/) ; la publication programmee, elle, reste
    une fonctionnalite du blog.
    """
    from app.utils import publish_scheduled_posts
    publish_scheduled_posts()


# Politique de securite du contenu : tout est servi depuis notre propre
# origine. Aucun domaine tiers n'est autorise — ni Google Fonts, ni un CDN de
# CKEditor : chaque requete vers un tiers revelerait a celui-ci l'adresse IP du
# lecteur, l'URL consultee et son User-Agent.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "media-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "connect-src 'self' ws: wss:; "
    "font-src 'self' data:; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
    "form-action 'self'; frame-src 'none'; worker-src 'self'"
)


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # no-referrer : aucune URL de ce site ne doit fuiter vers un site externe
    # quand un lecteur suit un lien sortant.
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault(
        'Permissions-Policy',
        'geolocation=(), microphone=(), camera=(), payment=(), usb=(), '
        'magnetometer=(), gyroscope=(), accelerometer=(), interest-cohort=()'
    )
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
    response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)

    # HSTS uniquement sur une connexion HTTPS effective : l'envoyer en clair
    # n'a aucun effet, et l'envoyer a tort peut rendre un site de test
    # inaccessible.
    if request.is_secure or os.environ.get('FORCE_HSTS', '').lower() in ('1', 'true', 'yes'):
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=63072000; includeSubDomains'
        )

    # Ne pas annoncer la pile serveur.
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




def _conversation_latest_message_id(admin_id, user_id):
    latest = Message.query.filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id))
    ).order_by(Message.id.desc()).first()
    return latest.id if latest else 0


def wait_for_conversation_message(admin_id, user_id, last_seen_id, timeout_seconds=25):
    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        latest_id = _conversation_latest_message_id(admin_id, user_id)
        if latest_id > last_seen_id:
            return True

        time.sleep(1)

    return False

# 🔹 Home Page
@app.route('/')
def index():
    posts = Post.query.filter(Post.is_published.is_(True)) \
        .order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


# 🔹 About Page
@app.route('/about')
def about():
    return render_template('about.html')


# 🔹 Editor Help Page
@app.route('/editor_help')
def editor_help():
    return render_template('editor_help.html')


# 🔹 Contact Page
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
    return render_template('contact.html', form=form)


def _require_visible_post(post):
    """404 pour un brouillon ou un article programme, sauf pour un admin."""
    if post.is_published:
        return
    if current_user.is_authenticated and current_user.is_admin:
        return
    abort(404)


# 🔹 View a Blog Post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    _require_visible_post(post)
    form = CommentForm()
    # Increment view counter once per session
    if request.method == 'GET':
        viewed_posts = session.get('viewed_posts', [])
        if post_id not in viewed_posts:
            post.views_count = (post.views_count or 0) + 1
            db.session.commit()
            viewed_posts.append(post_id)
            session['viewed_posts'] = viewed_posts

    if form.validate_on_submit():
        if current_user.is_authenticated:
            if _action_rate_limited('comment_submit', max_calls=12, window_seconds=300):
                flash('Too many comments in a short time. Please slow down.', 'danger')
                return redirect(url_for('post_detail', post_id=post.id))
            content = form.content.data.strip()
            if content:
                # Texte brut : converti (et echappe) au rendu par `comment_html`.
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
                    # Pas de socketio.emit : sans salon, l'evenement partait vers
                    # tous les sockets connectes. La notification est en base.
                
                # Check and award badges
                check_and_award_badges(current_user)
                
                db.session.commit()
                flash('Your comment has been posted!', 'success')
            else:
                flash('Comment cannot be empty.', 'danger')
        else:
            flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('post_detail', post_id=post.id))

    # Le BBCode de l'article est converti au rendu (filtre `bbcode`) : on ne
    # modifie plus l'objet ORM, qui risquait de persister du HTML au prochain commit.
    return render_template('post_detail.html', post=post, form=form)


# 🔹 Register a User
@app.route('/register', methods=['GET', 'POST'])
@rate_limit('register', max_calls=10, window_seconds=3600)
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        user.rotate_session_token()
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)


# TOTP : un code est valable un pas de 30 s, avec une tolerance d'un pas de
# chaque cote ; le pas accepte est memorise pour interdire le rejeu.
TOTP_STEP_SECONDS = 30
PRE_2FA_MAX_AGE = 300


def _totp_secret(user):
    """Secret TOTP en clair. Une ancienne valeur non chiffree est rendue telle quelle."""
    if not user or not user.totp_secret:
        return None
    return message_encryption.decrypt_message(user.totp_secret)


def _store_totp_secret(user, secret):
    user.totp_secret = message_encryption.encrypt_message(secret)


def _verify_totp(user, code, secret=None):
    """Retourne le pas TOTP accepte, ou None.

    Refuse un code deja utilise (`totp_last_counter`) : valid_window=1 laissait
    un code observe rejouable pendant ~90 s.
    """
    secret = secret or _totp_secret(user)
    code = re.sub(r'\s+', '', code or '')
    if not secret or not re.fullmatch(r'\d{6}', code):
        return None
    last = user.totp_last_counter if user.totp_last_counter is not None else -1
    current = int(time.time()) // TOTP_STEP_SECONDS
    try:
        generator = pyotp.TOTP(secret)
        for counter in (current - 1, current, current + 1):
            if hmac.compare_digest(generator.generate_otp(counter), code) and counter > last:
                return counter
    except Exception:
        return None
    return None


def _clear_pre_2fa():
    for key in ('pre_2fa_user_id', 'pre_2fa_remember', 'pre_2fa_at'):
        session.pop(key, None)


def _login_failure_key(username):
    return 'login:' + hashed_key((username or '').lower())


# 🔹 Login a User
@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', max_calls=30, window_seconds=300)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        fkey = _login_failure_key(form.username.data)
        # Verrouillage par pseudo (y compris inexistant : pas d'enumeration).
        # Meme message qu'un mot de passe faux, et pas de bcrypt.
        if too_many_failures(fkey, 10, 900):
            flash('Login failed. Check your username and password.', 'danger')
            return render_template('login.html', title='Login', form=form)

        user = User.query.filter_by(username=form.username.data).first()
        # Toujours une verification bcrypt : sans elle, une reponse instantanee
        # sur un pseudo inexistant contre ~250 ms sur un pseudo existant permet
        # d'enumerer les comptes au chronometre.
        password_ok = bcrypt.check_password_hash(
            user.password if user else _DUMMY_PASSWORD_HASH, form.password.data)
        if user and password_ok:
            # Le statut "suspendu" n'est revele qu'apres le mot de passe : sinon
            # il permet d'enumerer les comptes bannis.
            if user.is_banned:
                flash('This account has been suspended.', 'danger')
                return render_template('login.html', title='Login', form=form)
            clear_failures(fkey)
            if user.totp_enabled:
                # Store pre-auth state in session; do NOT log in yet
                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_remember'] = form.remember_me.data
                session['pre_2fa_at'] = int(time.time())
                return redirect(url_for('login_totp'))
            login_user(user, remember=form.remember_me.data)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        record_failure(fkey)
        flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)


# 🔹 TOTP second-step verification
@app.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """Second step: verify 6-digit TOTP code after successful password check."""
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        # No pending pre-auth — redirect to login
        return redirect(url_for('login'))

    # L'etat "mot de passe valide" expire : il ne doit pas survivre des heures.
    started = session.get('pre_2fa_at')
    if not isinstance(started, int) or int(time.time()) - started > PRE_2FA_MAX_AGE:
        _clear_pre_2fa()
        flash('The verification step expired. Please sign in again.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or not user.totp_enabled or user.is_banned:
        _clear_pre_2fa()
        return redirect(url_for('login'))

    form = TOTPVerifyForm()
    if form.validate_on_submit():
        # Limite par compte cote serveur : le cookie de session etant rejouable
        # par le client, un compteur qui y vivrait serait contournable.
        if _action_rate_limited('totp_verify', 5, 300, actor_key=f'pending:{user.id}'):
            _clear_pre_2fa()
            flash('Too many invalid codes. Please sign in again in a few minutes.', 'danger')
            return redirect(url_for('login'))

        counter = _verify_totp(user, form.code.data)
        if counter is not None:
            remember = session.pop('pre_2fa_remember', False)
            _clear_pre_2fa()
            user.totp_last_counter = counter
            # Ancien secret en clair : on le chiffre maintenant qu'il est prouve valide.
            stored = user.totp_secret
            if stored and message_encryption.decrypt_message(stored) == stored:
                _store_totp_secret(user, stored)
            db.session.commit()
            login_user(user, remember=remember)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('login_totp.html', form=form)


# 🔹 Logout a User
@app.route('/logout')
def logout():
    # Clear any pending pre-2FA session state
    _clear_pre_2fa()
    logout_user()
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


# 🔹 Admin Dashboard
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


# Adresse du widget de swap tiers. Centralisee ici pour que le gabarit n'ait
# pas a la coder en dur, et pour qu'il soit visible en un coup d'oeil qu'une
# origine externe est impliquee.
TROCADOR_WIDGET_URL = (
    'https://trocador.app/anonpay/?ticker_to=xmr&network_to=Mainnet'
    '&address=47wJbYtPB6SLd4P9PCwLcKfTgXCTnZGPwUuGSv3dPTGuG1RmhcB8LVQUVHATAAW1Q6ZVJQQ82EeC9Rzox7aWt6jgCtw54Pj'
    '&donation=True&amount=0.0001&name=Blog+Support'
    '&description=Thanks+for+supporting+the+blog&bgcolor='
)


# 🔹 Donate Page
@app.route('/donate', methods=['GET', 'POST'])
def donate():
    form = EmptyForm()

    if request.method == 'POST':
        try:
            amount = float((request.form.get('amount') or '0').strip())
        except ValueError:
            amount = None
        if amount is None or not math.isfinite(amount) or not 0 < amount <= 100000:
            flash('Please enter a valid amount.', 'danger')
            return redirect(url_for('donate'))
        # Seules les saisies valides comptent : une faute de frappe ne doit pas
        # consommer le quota.
        if _action_rate_limited('donate', 3, 3600):
            flash('Too many submissions. Please try again later.', 'danger')
            return redirect(url_for('donate'))
        new_donor = Donor(name='Anonymous', amount=round(amount, 4))
        db.session.add(new_donor)
        db.session.commit()
        flash("Thank you for your donation!", "success")
        return redirect(url_for('donate'))

    top_donors = Donor.query.order_by(Donor.amount.desc()).limit(5).all()

    # Le widget de swap tiers n'est charge que si le lecteur le demande
    # explicitement (?embed=1). Voir TROCADOR_WIDGET_URL.
    embed_widget = request.args.get('embed') == '1'
    response = Response(render_template(
        'donate.html',
        form=form,
        top_donors=top_donors,
        embed_widget=embed_widget,
        trocador_url=TROCADOR_WIDGET_URL,
    ))
    if embed_widget:
        # CSP assouplie pour cette seule reponse, et uniquement pour l'origine
        # du widget.
        response.headers['Content-Security-Policy'] = CONTENT_SECURITY_POLICY.replace(
            "frame-src 'none'", "frame-src https://trocador.app"
        )
    return response


# File Upload Configuration
UPLOAD_FOLDER = 'uploads'
MAX_UPLOAD_BYTES = int((os.environ.get('MAX_UPLOAD_BYTES') or str(10 * 1024 * 1024)).strip())
CHAT_ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp',
    'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', '7z',
    'mp3', 'mp4', 'avi', 'mov', 'mkv', 'csv', 'xls', 'xlsx',
    'ppt', 'pptx', 'json', 'xml', 'svg', 'webm', 'ogg'
}
PROFILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
# Pas de SVG : servi depuis la meme origine, un SVG peut embarquer du <script>.
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
# Garde-fous contre les bombes de decompression. 40 megapixels laisse passer
# tout appareil photo grand public ; au-dela c'est une image forgee.
MAX_IMAGE_PIXELS = 40_000_000
# Pillow leve DecompressionBombError au-dela de 2x cette valeur : meme limite
# partout, y compris pour les chemins qui n'appellent pas _validate_uploaded_file.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
MAX_IMAGE_SIDE = 12_000
ALLOWED_MIME_EXACT = {
    'application/pdf', 'application/zip', 'application/json', 'application/xml',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/x-7z-compressed', 'application/x-rar-compressed',
    'text/plain', 'text/csv'
}
ALLOWED_MIME_PREFIXES = ('image/', 'video/', 'audio/', 'text/')


def _file_ext(filename):
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower().strip()


def allowed_file(filename, allowed_exts=None):
    allowed_exts = allowed_exts or CHAT_ALLOWED_EXTENSIONS
    return _file_ext(filename) in allowed_exts


def _validate_uploaded_file(file_obj, allowed_exts=None, max_bytes=None, image_only=False):
    if not file_obj or not getattr(file_obj, 'filename', ''):
        return False, "No file selected."
    allowed_exts = allowed_exts or CHAT_ALLOWED_EXTENSIONS
    max_bytes = max_bytes or MAX_UPLOAD_BYTES
    ext = _file_ext(file_obj.filename)
    if ext not in allowed_exts:
        return False, "File extension not allowed."

    stream = file_obj.stream
    current_pos = stream.tell()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(current_pos)
    if size <= 0:
        return False, "Empty file."
    if size > max_bytes:
        return False, f"File too large (max {max_bytes // (1024 * 1024)} MB)."

    mime = (getattr(file_obj, 'mimetype', '') or '').lower().strip()
    if image_only:
        if not mime.startswith('image/'):
            return False, "Only image uploads are allowed."
    elif not (mime in ALLOWED_MIME_EXACT or any(mime.startswith(p) for p in ALLOWED_MIME_PREFIXES)):
        return False, "Unsupported MIME type."

    if ext in IMAGE_EXTENSIONS:
        try:
            stream.seek(0)
            with Image.open(stream) as img:
                # Bombe de decompression : un PNG de quelques kilo-octets peut
                # declarer 50000x50000 pixels et faire allouer des gigaoctets a
                # Pillow au moment du decodage. On refuse sur les dimensions
                # AVANT de decoder quoi que ce soit.
                width, height = img.size
                if width * height > MAX_IMAGE_PIXELS:
                    return False, "Image dimensions are too large."
                if width > MAX_IMAGE_SIDE or height > MAX_IMAGE_SIDE:
                    return False, "Image dimensions are too large."
                img.verify()
            stream.seek(0)
        except Exception:
            stream.seek(0)
            return False, "Invalid or corrupted image."

    return True, ""

def screen_uploaded_image(file_path, user):
    """Refuse une image figurant dans la liste de hash bloques.

    Retourne None si l'image passe. Sinon : met le fichier en quarantaine,
    bannit l'auteur, journalise l'evenement, et retourne un message d'erreur.

    A appeler AVANT le nettoyage des metadonnees : celui-ci ré-encode l'image et
    modifie donc son SHA-256. Le dHash, lui, survit aux deux.
    """
    from app.image_safety import check_image, quarantine_file
    from app.models import BlockedImageHash, BlockedUploadEvent

    try:
        match, distance = check_image(path=file_path)
    except Exception:
        # Un echec du controle ne doit pas laisser passer l'image en silence,
        # mais ne doit pas non plus bloquer un televersement legitime : on
        # journalise et on laisse passer, en le signalant a l'admin.
        app.logger.exception('Image screening failed; upload allowed unchecked.')
        return None

    if match is None:
        return None

    from app.image_safety import sha256_of_file
    digest = sha256_of_file(file_path)
    quarantined = quarantine_file(
        file_path,
        reason=f'hash match id={match.id} label={match.label or "-"} distance={distance}'
    )

    event = BlockedUploadEvent(
        user_id=getattr(user, 'id', None),
        matched_hash_id=match.id,
        distance=distance,
        sha256=digest,
        quarantine_name=quarantined,
    )
    db.session.add(event)

    # Bannissement immediat de l'auteur.
    if getattr(user, 'is_authenticated', False) and not user.is_admin:
        user.is_banned = True
        user.banned_at = datetime.utcnow()
        user.ban_reason = 'Blocked image upload'
        user.rotate_session_token()

    db.session.commit()

    app.logger.warning(
        'Blocked image upload: user_id=%s hash_id=%s distance=%s quarantine=%s',
        getattr(user, 'id', None), match.id, distance, quarantined
    )
    return 'This file cannot be uploaded.'


def random_upload_name(original_filename):
    """Nom de fichier aleatoire conservant seulement l'extension.

    L'ancien schema `chat_<user_id>_admin_<horodatage>_<nom original>` publiait
    l'identifiant de l'auteur, l'heure d'envoi et le nom du fichier tel qu'il
    existait sur sa machine — le tout dans une URL. On ne garde que l'extension.
    """
    ext = _file_ext(original_filename)
    if ext not in CHAT_ALLOWED_EXTENSIONS:
        ext = ''
    return f"{uuid.uuid4().hex}{('.' + ext) if ext else ''}"


def strip_image_metadata(file_path):
    """Supprime reellement les metadonnees d'une image (EXIF, GPS, XMP, ICC).

    L'implementation precedente *ajoutait* des tags EXIF factices ("Modified",
    "ChatUploader") et reecrivait chaque fichier en JPEG, quel que soit son
    format d'origine. Ici on reconstruit l'image a partir de ses seuls pixels :
    aucun bloc de metadonnees ne survit, et le format d'origine est conserve.
    """
    try:
        with Image.open(file_path) as image:
            fmt = image.format or 'PNG'
            image.load()
            # copy() travaille sur le tampon C (l'ancienne boucle `putdata(list(
            # getdata()))` allouait un objet Python par pixel : 3,6 Go pour un
            # PNG de 131 Ko). On ne garde que la transparence ; ni `exif=`, ni
            # `icc_profile=` ne sont passes a save().
            keep = {k: image.info[k] for k in ('transparency',) if k in image.info}
            clean = image.copy()
            clean.info = dict(keep)
            if fmt.upper() in ('JPEG', 'JPG'):
                clean.convert('RGB').save(file_path, 'JPEG', quality=88)
            elif fmt.upper() == 'WEBP':
                clean.save(file_path, 'WEBP', quality=88, method=6)
            elif fmt.upper() == 'GIF':
                clean.save(file_path, fmt, **keep)
            else:
                clean.save(file_path, fmt)
    except Exception:
        # Une image dont on n'a pas pu garantir le nettoyage ne doit pas etre
        # publiee : on la supprime plutot que de la servir avec ses coordonnees
        # GPS intactes.
        app.logger.warning('Metadata stripping failed; upload discarded.')
        try:
            os.remove(file_path)
        except OSError:
            pass
        raise


# Conserve pour compatibilite : tous les appels passent desormais par
# strip_image_metadata.
def modify_exif_data(file_path):
    strip_image_metadata(file_path)

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
            if is_valid:
                filename = random_upload_name(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                # Controle contre la liste de hash AVANT le nettoyage des
                # metadonnees, qui ré-encode l'image et change son SHA-256.
                if _file_ext(file.filename) in IMAGE_EXTENSIONS:
                    refusal = screen_uploaded_image(file_path, current_user)
                    if refusal:
                        flash(refusal, 'danger')
                        return redirect(url_for('index'))

                # Nettoyage des metadonnees ; en cas d'echec le fichier est
                # supprime et le message n'est pas enregistre.
                if _file_ext(file.filename) in IMAGE_EXTENSIONS:
                    try:
                        strip_image_metadata(file_path)
                    except Exception:
                        flash('Upload rejected: image metadata could not be removed.', 'danger')
                        return redirect(url_for('chat'))

                # Determine file type
                file_type = get_file_type(file.filename)

                # Save message with file using proper fields
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=_get_admin_user_id(),  # actual admin
                    file_path=filename,
                    file_type=file_type
                )
                message.set_encrypted_content(message_content or "")
                db.session.add(message)
                db.session.commit()
                publish_mobile_event('new_message', serialize_chat_message(message))
                flash("File sent!", "success")
            else:
                flash(f"File upload failed: {validation_msg}", "danger")

        elif message_content:
            # Save text message (chiffre au repos, comme les reponses admin)
            message = Message(
                sender_id=current_user.id,
                receiver_id=_get_admin_user_id(),  # actual admin
            )
            message.set_encrypted_content(message_content)
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            flash("Message sent!", "success")

        return redirect(url_for('chat'))

    # Uniquement la conversation entre l'utilisateur courant et l'admin.
    # La version precedente faisait `Message.query.all()` : n'importe quel
    # compte connecte lisait les conversations privees de tous les autres.
    admin_id = _get_admin_user_id()
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == admin_id)) |
        ((Message.sender_id == admin_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.desc()).all()

    return render_template('chat.html', form=form, messages=messages)

@socketio.on('connect')
def socket_connect(auth=None):
    # Une connexion anonyme n'a aucune raison d'exister : refusee des le depart.
    if not current_user.is_authenticated:
        return False


@socketio.on('message')
def handle_message(data):
    # Seule source de verite pour l'expediteur : la session serveur. Le client
    # ne fournit que le texte — jamais son propre identifiant.
    if not current_user.is_authenticated:
        return
    # Meme compteur que la route /chat.
    if _action_rate_limited('chat_submit', max_calls=30, window_seconds=300):
        return

    msg = (data or {}).get('msg', '').strip()
    if not msg:
        return
    if len(msg) > 5000:
        msg = msg[:5000]

    message = Message(sender_id=current_user.id, receiver_id=_get_admin_user_id())
    message.set_encrypted_content(msg)
    db.session.add(message)
    db.session.commit()
    publish_mobile_event('new_message', serialize_chat_message(message))

    # Accuse de reception a l'expediteur uniquement. L'ancien `broadcast=True`
    # rediffusait chaque message prive — avec le pseudo de son auteur — a tous
    # les clients WebSocket connectes.
    emit('message', {'msg': msg, 'mine': True})


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
    target_user = User.query.get_or_404(user_id)

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
                if is_valid:
                    filename = random_upload_name(file.filename)
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    refusal = screen_uploaded_image(file_path, current_user)
                    if refusal:
                        flash(refusal, 'danger')
                        return redirect(url_for('admin_chat_user', user_id=user_id))
                    # Media pipeline (strip EXIF, resize, WebP)
                    processed = process_image_file(file_path)
                    if processed != file_path:
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
                        file_path = processed
                    message.file_path = os.path.basename(file_path)
                    message.file_type = get_file_type(file.filename)
                else:
                    flash(f'File upload blocked: {validation_msg}', 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
            
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            
            # Pas de socketio.emit ici : sans salon (room), l'emission etait
            # diffusee a *tous* les clients WebSocket connectes, en clair et
            # avec le pseudo de l'admin. La page est de toute facon rechargee
            # par le redirect ci-dessous.

            flash('Message sent!', 'success')
            return redirect(url_for('admin_chat_user', user_id=user_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    latest_message_id = messages[-1].id if messages else 0

    return render_template('admin_chat_user.html', 
                         messages=messages, 
                         users=users, 
                         target_user=target_user,
                         latest_message_id=latest_message_id)


@app.route('/api/admin/mobile/ping', methods=['GET'])
@admin_api_required
def api_admin_mobile_ping():
    admin_user = request.admin_api_user
    return jsonify({
        'status': 'ok',
        'admin': {
            'id': admin_user.id,
            'username': admin_user.username
        }
    })


@app.route('/api/admin/mobile/conversations', methods=['GET'])
@admin_api_required
def api_admin_mobile_conversations():
    admin_user = request.admin_api_user
    users = User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()

    conversations = []
    for user in users:
        last_message = Message.query.filter(
            ((Message.sender_id == admin_user.id) & (Message.receiver_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.receiver_id == admin_user.id))
        ).order_by(Message.timestamp.desc()).first()

        conversations.append({
            'user': {
                'id': user.id,
                'username': user.username,
                'level': user.level,
                'experience_points': user.experience_points
            },
            'last_message': serialize_chat_message(last_message) if last_message else None
        })

    return jsonify({'conversations': conversations})


@app.route('/api/admin/mobile/conversations/<int:user_id>/messages', methods=['GET'])
@admin_api_required
def api_admin_mobile_messages(user_id):
    admin_user = request.admin_api_user
    limit = request.args.get('limit', default=50, type=int)
    limit = max(1, min(limit, 200))

    target_user = User.query.filter_by(id=user_id, is_admin=False).first_or_404()
    messages = Message.query.filter(
        ((Message.sender_id == admin_user.id) & (Message.receiver_id == target_user.id)) |
        ((Message.sender_id == target_user.id) & (Message.receiver_id == admin_user.id))
    ).order_by(Message.timestamp.desc()).limit(limit).all()

    messages = list(reversed(messages))
    return jsonify({
        'conversation': {
            'admin_id': admin_user.id,
            'user_id': target_user.id,
            'user_username': target_user.username
        },
        'messages': [serialize_chat_message(message) for message in messages]
    })


@app.route('/api/admin/mobile/conversations/<int:user_id>/messages', methods=['POST'])
@csrf.exempt
@admin_api_required
def api_admin_mobile_send_message(user_id):
    admin_user = request.admin_api_user
    target_user = User.query.filter_by(id=user_id, is_admin=False).first_or_404()

    payload = request.get_json(silent=True) or {}
    content = (payload.get('content') or '').strip()

    if not content:
        return jsonify({'error': 'Message content is required.'}), 400

    message = Message(
        sender_id=admin_user.id,
        receiver_id=target_user.id
    )
    message.set_encrypted_content(content)
    db.session.add(message)
    db.session.commit()

    serialized_message = serialize_chat_message(message)
    publish_mobile_event('new_message', serialized_message)

    return jsonify({'message': serialized_message}), 201


@app.route('/api/admin/mobile/stream', methods=['GET'])
@admin_api_required
def api_admin_mobile_stream():
    admin_user = request.admin_api_user
    subscriber_queue = queue.Queue(maxsize=100)

    with mobile_event_lock:
        mobile_event_subscribers.append(subscriber_queue)

    def event_stream():
        try:
            welcome = {
                'type': 'connected',
                'payload': {
                    'admin_id': admin_user.id,
                    'username': admin_user.username
                },
                'created_at': datetime.utcnow().isoformat() + 'Z'
            }
            yield f"data: {json.dumps(welcome)}\n\n"

            while True:
                try:
                    event = subscriber_queue.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    heartbeat = {'type': 'heartbeat', 'created_at': datetime.utcnow().isoformat() + 'Z'}
                    yield f"data: {json.dumps(heartbeat)}\n\n"
        finally:
            with mobile_event_lock:
                if subscriber_queue in mobile_event_subscribers:
                    mobile_event_subscribers.remove(subscriber_queue)

    response = Response(stream_with_context(event_stream()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


def _attachment_message(filename):
    """Retourne le Message dont `filename` est la piece jointe, s'il existe."""
    base = os.path.basename(filename)
    return Message.query.filter(
        (Message.file_path == base) | (Message.file_path.like(f'%/{base}'))
    ).first()


def _serve_upload(filename):
    """Sert un fichier de uploads/ en respectant la confidentialite du chat.

    Une piece jointe de conversation n'est lisible que par ses deux
    correspondants (et par un admin). Auparavant l'URL etait publique : le nom
    de fichier contenait l'identifiant de l'auteur et un horodatage, ce qui la
    rendait devinable, et rien n'exigeait d'etre connecte pour la telecharger.
    """
    safe_name = os.path.basename(filename)
    if safe_name != filename or safe_name in ('', '.', '..'):
        abort(404)

    message = _attachment_message(safe_name)
    if message is not None:
        if not current_user.is_authenticated:
            abort(404)
        allowed = (
            current_user.id in (message.sender_id, message.receiver_id)
            or current_user.is_admin
        )
        if not allowed:
            abort(404)

    response = send_from_directory(_uploads_root(), safe_name)
    # Pas de mise en cache partagee pour une piece jointe privee.
    if message is not None:
        response.headers['Cache-Control'] = 'private, no-store'
    # Empeche l'execution d'un contenu servi depuis notre origine.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers.setdefault('Content-Security-Policy', "default-src 'none'; sandbox")
    return response


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Route to serve uploaded files"""
    return _serve_upload(filename)


@app.route('/static/uploads/<path:filename>')
def static_uploaded_file(filename):
    """Route to serve uploaded files from static/uploads"""
    return _serve_upload(filename)


# 🔹 File Upload Route



@app.route('/manage_posts', methods=['GET', 'POST'])
@admin_required
def manage_posts():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        # Pas de date = pas de programmation : sans `or utcnow()`, tout
        # brouillon etait publie a la requete suivante.
        scheduled_date = form.scheduled_date.data
        is_published = bool(form.is_published.data)
        post = Post(
            title=title,
            content=content,
            author_id=current_user.id,
            scheduled_date=scheduled_date,
            is_published=is_published,
            is_draft=not is_published and scheduled_date is None,
        )
        db.session.add(post)
        db.session.commit()
        
        # Add experience points for creating a post
        current_user.add_experience(10)
        
        # Vérifier et attribuer les badges
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
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    form = EmptyForm()
    return render_template('manage_comments.html', comments=comments, form=form)

@app.route('/site_statistics')
@admin_required
def site_statistics():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    # Trouver l'utilisateur avec le plus de posts
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

    return render_template('manage_banners.html', banners=banners, form=form)



UPLOAD_FILE_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def get_file_type(filename):
    """Détermine le type de fichier basé sur l'extension"""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv']:
        return 'video'
    else:
        return 'file'

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

    filename = random_upload_name(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    # Save file
    file.save(file_path)

    refusal = screen_uploaded_image(file_path, current_user)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('index'))

    # Verify if it's a valid image by trying to open it with PIL
    try:
        with Image.open(file_path) as img:
            img.verify()  # Quick integrity check
    except Exception:
        os.remove(file_path)  # Remove file if it's not a valid image
        flash('Invalid image file!', 'danger')
        return redirect(url_for('chat'))

    # Modify image metadata
    modify_exif_data(file_path)

    flash('Image uploaded and metadata modified successfully!', 'success')
    return redirect(url_for('chat'))

@app.route('/manage_pages', methods=['GET', 'POST'])
@admin_required
def manage_pages():
    pages = StaticPage.query.all()
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, slug=form.slug.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('manage_pages'))

    return render_template('manage_pages.html', pages=pages, form=form)




@app.route('/demote_user/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        user.is_admin = False
        user.rotate_session_token()
        db.session.commit()
        flash(f'User {user.username} has been demoted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_page', methods=['GET', 'POST'])
@admin_required
def create_page():
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash('New page created!', 'success')
        return redirect(url_for('manage_pages'))

    return render_template('create_page.html', form=form)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Les lignes qui pointent vers l'article ou ses commentaires (NOT NULL ou
    # cle etrangere) doivent partir avant lui : sinon IntegrityError -> 500.
    comment_ids = [c.id for c in Comment.query.filter_by(post_id=post.id).all()]
    try:
        Like.query.filter_by(post_id=post.id).delete(synchronize_session=False)
        if comment_ids:
            Like.query.filter(Like.comment_id.in_(comment_ids)) \
                .delete(synchronize_session=False)
            Notification.query.filter(Notification.related_comment_id.in_(comment_ids)) \
                .update({'related_comment_id': None}, synchronize_session=False)
            Comment.query.filter(Comment.id.in_(comment_ids)) \
                .update({'parent_id': None}, synchronize_session=False)
        Notification.query.filter_by(related_post_id=post.id) \
            .update({'related_post_id': None}, synchronize_session=False)
        if comment_ids:
            Comment.query.filter(Comment.id.in_(comment_ids)) \
                .delete(synchronize_session=False)
        Revision.query.filter_by(post_id=post.id).delete(synchronize_session=False)
        db.session.expire_all()
        db.session.delete(Post.query.get(post.id))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('This post could not be deleted.', 'danger')
        return redirect(url_for('manage_posts'))
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_posts'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Supprime un compte et tout ce qui y est rattache.

    Les commentaires restent (affiches « [deleted] »), les articles passent a
    l'admin qui supprime. Les messages du chat, eux, sont definitivement
    supprimes : l'operation exige donc `purge_messages=1` des qu'il y en a.
    """
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_users'))
    if user.is_admin:
        flash('Demote this administrator before deleting the account.', 'danger')
        return redirect(url_for('manage_users'))

    messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)).all()
    if messages and request.form.get('purge_messages') != '1':
        flash(f'{user.username} has {len(messages)} chat message(s). Deleting the '
              'account erases them permanently: tick "also delete messages" and '
              'confirm.', 'danger')
        return redirect(url_for('manage_users'))

    from app.models import BlockedUploadEvent, SiteText, SiteTextRevision
    username = user.username
    files = [m.file_path for m in messages if m.file_path]
    if user.profile_picture:
        files.append(user.profile_picture)
    try:
        for comment in Comment.query.filter_by(author_id=user.id).all():
            comment.author_id = None
        for like in Like.query.filter_by(user_id=user.id).all():
            if like.post_id:
                target = Post.query.get(like.post_id)
            else:
                target = Comment.query.get(like.comment_id)
            if target is not None:
                target.likes_count = max(0, (target.likes_count or 0) - 1)
            db.session.delete(like)
        for message in messages:
            db.session.delete(message)
        Notification.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        BlockedUploadEvent.query.filter_by(user_id=user.id) \
            .update({'user_id': None}, synchronize_session=False)
        SiteText.query.filter_by(updated_by_id=user.id) \
            .update({'updated_by_id': None}, synchronize_session=False)
        SiteTextRevision.query.filter_by(changed_by_id=user.id) \
            .update({'changed_by_id': None}, synchronize_session=False)
        for post in Post.query.filter_by(author_id=user.id).all():
            post.author_id = current_user.id
        db.session.flush()
        db.session.delete(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('This account could not be deleted.', 'danger')
        return redirect(url_for('manage_users'))

    # Les fichiers ne partent qu'une fois la base validee.
    for stored in files:
        path = _absolute_upload_path(stored)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
    flash(f'User {username} deleted.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/promote_user/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    user.rotate_session_token()
    db.session.commit()
    flash(f"{user.username} has been promoted to admin.", "success")
    return redirect(url_for('manage_users'))






@app.route("/delete_comment/<int:comment_id>/<int:post_id>", methods=["POST"]) 
@rate_limit('delete_comment', max_calls=15, window_seconds=300)
@login_required
def delete_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)

    # Admin can delete everything, otherwise user can only delete their own comments
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully!", "success")
    return redirect(url_for("post_detail", post_id=post_id))



@app.route("/posts")
def post_list():
    posts = Post.query.filter(Post.is_published.is_(True)) \
        .order_by(Post.date_posted.desc()).all()
    return render_template("post_list.html", posts=posts)

@app.route("/reply_to_comment/<int:post_id>/<int:comment_id>", methods=["POST"])
@rate_limit('reply_to_comment', max_calls=10, window_seconds=300)
@login_required
def reply_to_comment(post_id, comment_id):
    post = Post.query.get_or_404(post_id)
    _require_visible_post(post)
    parent_comment = Comment.query.get_or_404(comment_id)

    form = CommentForm()

    if form.validate_on_submit():
        content = form.content.data.strip()
        if not content:
            flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
            return redirect(url_for("post_detail", post_id=post.id))
        reply = Comment(
            content=content,
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
                message=f'Someone replied to your comment',
                related_post_id=post.id,
                related_comment_id=reply.id
            )
            db.session.add(notification)
        
        # Vérifier et attribuer les badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash("Your reply has been added!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
    return redirect(url_for("post_detail", post_id=post.id))


@app.route("/edit_comment/<int:comment_id>/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)
    post = Post.query.get_or_404(post_id)

    # L'admin peut modifier tous les commentaires, sinon l'utilisateur ne peut modifier que les siens
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    form = CommentForm()
    if form.validate_on_submit():
        content = form.content.data.strip()
        if not content:
            flash("Comment cannot be empty.", "danger")
            return redirect(url_for("edit_comment", comment_id=comment.id, post_id=post_id))
        # Texte brut + BBCode : une ligne ancienne (HTML) devient ainsi du texte
        # propre des qu'elle est modifiee.
        comment.content = content
        comment.content_format = 'bbcode'
        db.session.commit()
        flash("Comment updated!", "success")
        return redirect(url_for("post_detail", post_id=post_id))

    # Pre-remplissage : une ancienne ligne HTML est affichee en texte (en
    # memoire seulement, la base n'est pas touchee avant l'enregistrement).
    form.content.data = (comment.content if comment.content_format == 'bbcode'
                         else html_to_text(comment.content))
    return render_template("edit_comment.html", title="Edit Comment", form=form, post=post, comment=comment)  # 🔥 Passe `post`


def _revoke_like_reward(author, points, related_post_id=None, related_comment_id=None):
    """Annule l'effet d'un like retire : XP et notification non lue.

    Sans cela, like/unlike en boucle donnait de l'XP sans limite et une
    notification par cycle. Le niveau n'est jamais abaisse.
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


# 🔹 Système de Likes/Upvotes
@app.route('/like_post/<int:post_id>', methods=['POST'])
@rate_limit('like_post', max_calls=20, window_seconds=300)
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    _require_visible_post(post)
    
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
        post.likes_count += 1
        
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
        
        flash('Article liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@rate_limit('like_comment', max_calls=20, window_seconds=300)
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
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
        comment.likes_count += 1
        
        # Add experience points to comment author
        if comment.author_id and comment.author_id != current_user.id:
            comment.author.add_experience(2)
            
            # Créer une notification pour l'auteur
            notification = Notification(
                user_id=comment.author_id,
                type='like',
                title='Comment liked!',
                message=f'{current_user.username} liked your comment',
                related_comment_id=comment_id,
                related_post_id=comment.post_id
            )
            db.session.add(notification)
        
        flash('Comment liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=comment.post_id))


# 🔹 Système de Notifications
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
    notification = Notification.query.get_or_404(notification_id)
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


# 🔹 Système de Badges et Niveaux
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_posts = Post.query.filter_by(author_id=user_id, is_published=True).order_by(Post.date_posted.desc()).limit(5).all()
    user_comments = Comment.query.filter_by(author_id=user_id).order_by(Comment.date_posted.desc()).limit(5).all()
    
    # Calculer les statistiques
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


# Function to create default badges
def create_default_badges():
    """Creates default system badges"""
    default_badges = [
        {
            'name': 'Premier Post',
            'description': 'A publié son premier article',
            'icon': 'fas fa-feather-alt',
            'color': '#8b93ff',
            'condition': 'first_post',
            'points_reward': 50
        },
        {
            'name': 'Commentateur Actif',
            'description': 'A publié 10 commentaires',
            'icon': 'fas fa-comments',
            'color': '#51cf66',
            'condition': '10_comments',
            'points_reward': 30
        },
        {
            'name': 'Auteur Prolifique',
            'description': 'A publié 5 articles',
            'icon': 'fas fa-pen-fancy',
            'color': '#ffd43b',
            'condition': '5_posts',
            'points_reward': 100
        },
        {
            'name': 'Populaire',
            'description': 'Un de ses articles a reçu 10 likes',
            'icon': 'fas fa-fire',
            'color': '#ff6b6b',
            'condition': '10_likes_post',
            'points_reward': 75
        },
        {
            'name': 'Niveau 5',
            'description': 'A atteint le niveau 5',
            'icon': 'fas fa-star',
            'color': '#9c88ff',
            'condition': 'level_5',
            'points_reward': 0
        }
    ]
    
    for badge_data in default_badges:
        existing_badge = Badge.query.filter_by(name=badge_data['name']).first()
        if not existing_badge:
            badge = Badge(**badge_data)
            db.session.add(badge)
    
    db.session.commit()


# Function to check and award badges
def check_and_award_badges(user):
    """Checks and awards badges to a user"""
    badges = Badge.query.all()
    
    for badge in badges:
        if badge.name not in user.get_badges():
            should_award = False
            
            if badge.condition == 'first_post':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 1
            elif badge.condition == '10_comments':
                should_award = Comment.query.filter_by(author_id=user.id).count() >= 10
            elif badge.condition == '5_posts':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 5
            elif badge.condition == '10_likes_post':
                should_award = db.session.query(Post).filter_by(author_id=user.id)\
                    .filter(Post.likes_count >= 10).first() is not None
            elif badge.condition == 'level_5':
                should_award = user.level >= 5
            
            if should_award:
                user.add_badge(badge.name)
                user.add_experience(badge.points_reward)
                
                # Create notification
                notification = Notification(
                    user_id=user.id,
                    type='badge',
                    title='New badge earned!',
                    message=f'You earned the badge "{badge.name}": {badge.description}',
                )
                db.session.add(notification)
                
                flash(f'Congrats! You unlocked the badge "{badge.name}"!', 'success')


# 🔹 Route pour initialiser les badges (à appeler une seule fois)
@app.route('/init_badges')
@admin_required
def init_badges():
    create_default_badges()
    flash('Default badges created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# 🔹 Édition du profil utilisateur
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(original_username=current_user.username)
    
    if form.validate_on_submit():
        # Mettre à jour le nom d'utilisateur
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
            if is_valid:
                filename = random_upload_name(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                refusal = screen_uploaded_image(file_path, current_user)
                if refusal:
                    flash(refusal, 'danger')
                    return redirect(url_for('index'))

                try:
                    strip_image_metadata(file_path)
                except Exception:
                    flash('Upload rejected: image metadata could not be removed.', 'danger')
                    return redirect(url_for('edit_profile'))

                # Remove old photo if it exists
                old_photo = _absolute_upload_path(current_user.profile_picture)
                if old_photo and os.path.exists(old_photo):
                    os.remove(old_photo)

                current_user.profile_picture = filename
            else:
                flash(f'Profile picture rejected: {validation_msg}', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    # Pre-fill form with current data
    form.username.data = current_user.username
    
    return render_template('edit_profile.html', form=form)


@app.route('/account/password', methods=['GET', 'POST'])
@login_required
@rate_limit('change_password', max_calls=5, window_seconds=600)
def change_password():
    """Changement de mot de passe.

    Aussi la sortie obligatoire quand `must_change_password` est pose : le
    script de deploiement genere un mot de passe aleatoire, et cette page est
    ce qui transforme « il faut le changer » en contrainte effective.
    """
    form = ChangePasswordForm()
    forced = bool(current_user.must_change_password)

    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
            flash('The current password is not correct.', 'danger')
            return render_template('change_password.html', form=form, forced=forced)

        current_user.password = bcrypt.generate_password_hash(
            form.new_password.data).decode('utf-8')
        current_user.must_change_password = False
        # Invalide les autres sessions et cookies "remember" de ce compte.
        current_user.rotate_session_token()
        db.session.commit()

        # Rotation de session : l'identifiant de session precedent ne doit plus
        # ouvrir le compte apres un changement de mot de passe.
        user = current_user._get_current_object()
        logout_user()
        session.clear()
        login_user(user)

        flash('Password changed.', 'success')
        return redirect(url_for('user_profile', user_id=user.id))

    return render_template('change_password.html', form=form, forced=forced)


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
        counter = _verify_totp(current_user, form.code.data, secret=pending_secret)
        if counter is not None:
            _store_totp_secret(current_user, pending_secret)
            current_user.totp_last_counter = counter
            current_user.totp_enabled = True
            # Les sessions et cookies "remember" deja emis ne valent plus ;
            # la session en cours est reouverte avec le nouveau jeton.
            current_user.rotate_session_token()
            db.session.commit()
            session.pop('totp_pending_secret', None)
            login_user(current_user._get_current_object())
            flash('Two-factor authentication has been enabled!', 'success')
            return redirect(url_for('user_profile', user_id=current_user.id))
        else:
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
        if _action_rate_limited('totp_disable', 5, 300,
                                actor_key=f'totp_disable:{current_user.id}'):
            flash('Too many attempts. Please wait a few minutes.', 'danger')
            return render_template('totp_disable.html', form=form)

        if not bcrypt.check_password_hash(current_user.password, form.password.data):
            flash('Incorrect password.', 'danger')
            return render_template('totp_disable.html', form=form)

        if _verify_totp(current_user, form.code.data) is None:
            flash('Invalid authentication code.', 'danger')
            return render_template('totp_disable.html', form=form)

        current_user.totp_enabled = False
        current_user.totp_secret = None
        current_user.totp_last_counter = None
        current_user.rotate_session_token()
        db.session.commit()
        login_user(current_user._get_current_object())
        flash('Two-factor authentication has been disabled.', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))

    return render_template('totp_disable.html', form=form)
