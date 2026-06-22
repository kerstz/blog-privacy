import os
from datetime import timedelta

class Config:
    # Secret key for Flask — required, no predictable default (public repo)
    SECRET_KEY = os.environ['SECRET_KEY']

    # Base directory path
    BASEDIR = os.path.abspath(os.path.dirname(__file__))

    # SQLite database connection
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(BASEDIR, "instance/blog.db")}'

    # Disable modification tracking for better performance
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)
    SESSION_COOKIE_SECURE = True  # Enable secure cookies (HTTPS only)
    SESSION_COOKIE_HTTPONLY = True  # Prevent cookie access via JavaScript
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection

    # Additional configurations
