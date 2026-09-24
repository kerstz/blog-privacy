"""Maintenance commands (run with `flask <command>`)."""
import os

import click

from app import app, db
from app.encryption import message_encryption
from app.models import Message, User
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
