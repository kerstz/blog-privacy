import os
import sys
import logging

from app import app as application, socketio

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

if __name__ == '__main__':
    # Development server only (production: gunicorn wsgi:application behind HTTPS). Never enable debug mode on a public host
    # (the Werkzeug debugger allows remote code execution).
    socketio.run(application,
                 host=os.environ.get('HOST', '127.0.0.1'),
                 port=int(os.environ.get('PORT', '5000')),
                 debug=False, allow_unsafe_werkzeug=True)
