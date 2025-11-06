import sys
import logging

# Ajoutez le chemin de votre application au sys.path


from app import app as application

# (Optionnel) Pour les logs
logging.basicConfig(stream=sys.stderr)
