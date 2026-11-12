import logging
import os
import sys

from app import app as application

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# gunicorn treats "Server" as a hop-by-hop header: it drops the neutral value
# set by the app and always sends "Server: gunicorn". An onion service served
# by gunicorn directly (deploy/deploy-onion.sh, no reverse proxy) would thus
# advertise its software stack, a fingerprint that helps link it to other
# servers. Replace the name gunicorn puts in that header.
try:
    import gunicorn.http.wsgi as _gunicorn_wsgi
    _gunicorn_wsgi.SERVER = 'server'
except ImportError:  # pragma: no cover - development server without gunicorn
    pass

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
