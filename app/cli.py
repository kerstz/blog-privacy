"""Maintenance commands (run with `flask <command>`)."""
import os

import click

from app import app, db
from app.encryption import message_encryption
from datetime import datetime, timedelta

from app.models import CONTACT_RETENTION_DAYS, ContactMessage, Message, User
from app.utils import (clear_failures, clear_rate_limit, hashed_key,
                       reset_security_state)
from app.services import ENCRYPTED_SUFFIX, _absolute_upload_path, encrypt_upload_in_place


def _encrypt_stored_file(stored_path):
    """Encrypt one legacy plaintext upload; returns the new stored path or None."""
    if not stored_path or stored_path.endswith(ENCRYPTED_SUFFIX):
        return None
    absolute = _absolute_upload_path(stored_path)
    if not os.path.isfile(absolute):
        return None
    encrypted = encrypt_upload_in_place(absolute)
    return f"{os.path.dirname(stored_path) or 'uploads'}/{os.path.basename(encrypted)}"


@app.cli.command('encrypt-legacy')
def encrypt_legacy():
    """Encrypt chat messages and uploaded files still stored in plaintext.

    Idempotent and safe to run on every update: rows/files that are already
    encrypted are left untouched; a file is only replaced once its encrypted
    copy is written and verified.
    """
    messages = files = 0
    for message in Message.query.all():
        if message.content and not message_encryption.is_ciphertext(message.content):
            message.set_encrypted_content(message.content)
            messages += 1
        elif not message.content:
            message.is_encrypted = True
        new_path = _encrypt_stored_file(message.file_path)
        if new_path:
            message.file_path = new_path
            files += 1
        db.session.commit()
    for user in User.query.filter(User.profile_picture.isnot(None)).all():
        new_path = _encrypt_stored_file(user.profile_picture)
        if new_path:
            user.profile_picture = new_path
            files += 1
            db.session.commit()
    click.echo(f"Encrypted {messages} legacy message(s) and {files} file(s).")


@app.cli.command('rotate-key')
@click.option('--dry-run', is_flag=True, help='Only check that everything can be re-encrypted.')
def rotate_key(dry_run):
    """Re-encrypt messages, 2FA secrets and uploads with the current key.

    Run after moving the old values to ENCRYPTION_OLD_KEY / ENCRYPTION_OLD_SALT /
    ENCRYPTION_OLD_ITERATIONS and setting the new ENCRYPTION_* values (also
    the way to raise ENCRYPTION_ITERATIONS on an existing install). Idempotent:
    data already under the current key is simply re-encrypted again. Exits
    with an error if something could not be read, so the old key must not be
    removed before a clean run.
    """
    from cryptography.fernet import InvalidToken
    from app.models import User
    from app.services import _uploads_root, write_token_file

    if not message_encryption.has_previous_key:
        raise click.UsageError('ENCRYPTION_OLD_KEY is not set: nothing to rotate from. '
                               'See SECURITY.md, "Rotating the encryption key".')
    counts = {'messages': 0, 'totp': 0, 'files': 0}
    failures = []

    for message in Message.query.filter(Message.is_encrypted.is_(True)).all():
        if not message.content or not message_encryption.is_ciphertext(message.content):
            continue  # empty or legacy plaintext (flask encrypt-legacy)
        rotated = message_encryption.rotate_message(message.content)
        if not dry_run:
            message.content = rotated
        counts['messages'] += 1
    for user in User.query.filter(User.totp_secret.isnot(None)).all():
        if not message_encryption.is_ciphertext(user.totp_secret):
            continue  # legacy plaintext secret, encrypted at the next login
        rotated = message_encryption.rotate_message(user.totp_secret)
        if not dry_run:
            user.totp_secret = rotated
        counts['totp'] += 1
    if not dry_run:
        db.session.commit()

    root = _uploads_root()
    names = sorted(os.listdir(root)) if os.path.isdir(root) else []
    for name in names:
        path = os.path.join(root, name)
        if not name.endswith(ENCRYPTED_SUFFIX) or not os.path.isfile(path):
            continue
        with open(path, 'rb') as fh:
            token = fh.read()
        try:
            rotated = message_encryption.rotate_bytes(token)
        except InvalidToken:
            failures.append(name)
            continue
        if not dry_run:
            write_token_file(path, rotated)
        counts['files'] += 1

    verb = 'Would re-encrypt' if dry_run else 'Re-encrypted'
    click.echo(f"{verb} {counts['messages']} message(s), {counts['totp']} 2FA secret(s) "
               f"and {counts['files']} file(s).")
    if failures:
        click.echo(f"{len(failures)} file(s) could not be decrypted with any key: "
                   + ', '.join(failures[:10]), err=True)
        raise SystemExit(1)
    if not dry_run:
        click.echo('Done. Remove ENCRYPTION_OLD_KEY / ENCRYPTION_OLD_SALT / '
                   'ENCRYPTION_OLD_ITERATIONS from the environment and restart the app.')


@app.cli.command('maintenance')
@click.argument('state', type=click.Choice(['on', 'off', 'status']))
def maintenance(state):
    """Maintenance mode: visitors get a 503 page, admins keep the site."""
    from app.services import maintenance_enabled, maintenance_flag_path, set_maintenance
    if state != 'status':
        set_maintenance(state == 'on')
    click.echo(f"Maintenance mode: {'ON' if maintenance_enabled() else 'off'} "
               f"(flag file {maintenance_flag_path()})")


@app.cli.command('unlock')
@click.argument('username', required=False)
@click.option('--all', 'unlock_all', is_flag=True,
              help='Clear every rate limit and failure counter.')
def unlock(username, unlock_all):
    """Clear the login lockout of USERNAME (or everything with --all)."""
    if unlock_all:
        reset_security_state()
        click.echo('All rate limits and failure counters cleared.')
        return
    if not username:
        raise click.UsageError('Give a USERNAME or use --all.')
    name = username.strip()
    clear_failures('login:' + hashed_key(name.lower()))        # web login
    clear_failures('admin_api:user:' + hashed_key(name.lower()))  # mobile API
    clear_rate_limit('login:k:' + hashed_key(name.lower()))    # login rate limit
    user = User.query.filter_by(username=name).first()
    if user:
        for prefix in ('totp_fail', 'totp_setup_fail', 'totp_disable_fail', 'reauth_fail',
                       '2fa_fail_day', 'alert_2fa_day'):
            clear_rate_limit(f'{prefix}:{user.id}')
    click.echo(f'Lockout cleared for {name}.')


@app.cli.command('purge-messages')
@click.option('--days', required=True, type=click.IntRange(min=1),
              help='Delete chat messages (and their attachments) older than this many days.')
@click.option('--dry-run', is_flag=True, help='Only count what would be deleted.')
def purge_messages(days, dry_run):
    """Delete old chat messages and their attachment files (data minimisation).

    What is no longer on the server cannot be read by whoever seizes it. The
    period is the operator's choice: there is no default. Run it from cron,
    e.g. weekly: `flask purge-messages --days 180`.
    """
    from app.services import _absolute_upload_path

    cutoff = datetime.utcnow() - timedelta(days=days)
    old = Message.query.filter(Message.timestamp < cutoff).all()
    files = {m.file_path for m in old if m.file_path}
    # A file still referenced by a newer message or used as a profile picture stays.
    kept = {m.file_path for m in Message.query.filter(Message.timestamp >= cutoff,
                                                      Message.file_path.in_(files))} if files else set()
    kept |= {u.profile_picture for u in User.query.filter(User.profile_picture.in_(files))} if files else set()
    doomed = sorted(files - kept)
    if dry_run:
        click.echo(f"Would delete {len(old)} message(s) and {len(doomed)} attachment(s) "
                   f"older than {days} day(s).")
        return
    for message in old:
        db.session.delete(message)
    db.session.commit()
    removed = 0
    for stored in doomed:
        path = _absolute_upload_path(stored)
        if path and os.path.isfile(path):
            os.remove(path)
            removed += 1
    click.echo(f"Deleted {len(old)} message(s) and {removed} attachment(s) older than {days} day(s).")


@app.cli.command('purge-notifications')
@click.option('--days', default=90, show_default=True, type=click.IntRange(min=1),
              help='Delete notifications older than this many days.')
def purge_notifications(days):
    """Delete old notifications (they keep who liked or answered what, and when)."""
    from app.models import Notification
    cutoff = datetime.utcnow() - timedelta(days=days)
    count = Notification.query.filter(Notification.created_at < cutoff).delete()
    db.session.commit()
    click.echo(f"Deleted {count} notification(s) older than {days} day(s).")


@app.cli.command('purge-contact')
@click.option('--days', default=CONTACT_RETENTION_DAYS, show_default=True, type=click.IntRange(min=0),
              help='Delete contact messages older than this many days.')
def purge_contact(days):
    """Delete old contact messages (GDPR retention)."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    count = ContactMessage.query.filter(ContactMessage.timestamp < cutoff).delete()
    db.session.commit()
    click.echo(f"Deleted {count} contact message(s) older than {days} day(s).")
