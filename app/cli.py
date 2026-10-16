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
        for prefix in ('totp_fail', 'totp_setup_fail', 'totp_disable_fail', 'reauth_fail'):
            clear_rate_limit(f'{prefix}:{user.id}')
    click.echo(f'Lockout cleared for {name}.')


@app.cli.command('purge-contact')
@click.option('--days', default=CONTACT_RETENTION_DAYS, show_default=True, type=click.IntRange(min=0),
              help='Delete contact messages older than this many days.')
def purge_contact(days):
    """Delete old contact messages (GDPR retention)."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    count = ContactMessage.query.filter(ContactMessage.timestamp < cutoff).delete()
    db.session.commit()
    click.echo(f"Deleted {count} contact message(s) older than {days} day(s).")
