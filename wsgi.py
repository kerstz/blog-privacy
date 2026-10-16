import logging
import os
import sys

from app import app as application

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

if __name__ == '__main__':
    # Development server only (production: gunicorn wsgi:application behind
    # HTTPS). `python wsgi.py` is the documented start command. Never enable
    # FLASK_DEBUG on a public host (the Werkzeug debugger allows remote code
    # execution).
    application.run(
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', '5000')),
        debug=os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes'),
    )
