import logging
import os
import sys

from app import app as application
from app import socketio

# (Optionnel) Pour les logs
logging.basicConfig(stream=sys.stderr)

if __name__ == '__main__':
    # `python wsgi.py` est la commande de demarrage documentee dans le README,
    # mais ce fichier ne faisait qu'exposer `application` : rien ne se lancait.
    # socketio.run() est necessaire ici, app.run() ne servirait pas le WebSocket.
    socketio.run(
        application,
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', '5000')),
        debug=os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes'),
        allow_unsafe_werkzeug=True,
    )
