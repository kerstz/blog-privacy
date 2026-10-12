import logging
import os
import sys

from app import app as application
from app import socketio

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

if __name__ == '__main__':
    # Development server only (production: gunicorn wsgi:application behind
    # HTTPS). `python wsgi.py` is the documented start command; socketio.run()
    # is required here, app.run() would not serve the WebSocket. Never enable
    # FLASK_DEBUG on a public host (the Werkzeug debugger allows remote code
    # execution).
    socketio.run(
        application,
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', '5000')),
        debug=os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes'),
        allow_unsafe_werkzeug=True,
    )
