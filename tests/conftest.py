"""Shared test setup: one process can run every test file together.

The environment is prepared BEFORE `app` is imported (the app reads it at
import time) and nothing here ever points at instance/ or a real database:
databases and the rate-limiter state live in a throwaway directory.
"""
import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix='blog-tests-')
os.environ.setdefault('SECRET_KEY', 't' * 48)
os.environ.setdefault('ENCRYPTION_KEY', 'k' * 32)
os.environ.setdefault('ENCRYPTION_SALT', 's' * 16)
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_TMP}/t.db')
os.environ.setdefault('SECURITY_STATE_DB', f'{_TMP}/s.db')
os.environ['SESSION_COOKIE_SECURE'] = '0'
for _name in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_ADMIN_CHAT_ID'):
    os.environ.pop(_name, None)


@pytest.fixture(autouse=True)
def _antispam_off_and_clean_limits():
    from app import app, utils
    app.config['ANTISPAM_ENABLED'] = False
    utils.reset_security_state()
    # The mobile API is off by default; most tests exercise it, so enable it
    # (test_mobile_api_disabled_by_default removes the variable itself).
    os.environ['MOBILE_API_ENABLED'] = 'true'
    yield
    os.environ.pop('MOBILE_API_ENABLED', None)
