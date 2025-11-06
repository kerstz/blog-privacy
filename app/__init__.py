from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_ckeditor import CKEditor
from flask_socketio import SocketIO
from datetime import timedelta
from markupsafe import Markup
import re
import os

from flask_socketio import SocketIO
# Initialisation de l'application
app = Flask(__name__)

# Configuration de l'application
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration CKEditor
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'

# Initialisation des extensions
ckeditor = CKEditor(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)


# Importez routes, models et client après l'initialisation
from app import routes, models, chat

# Fonction de chargement de l'utilisateur pour Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# Injecter des modèles dans le contexte global de Jinja2 pour les rendre disponibles dans toutes les templates
@app.context_processor
def inject_models():
    from app.models import Banner
    return dict(Banner=Banner)

# Définition du filtre `urlize` pour transformer les URLs en liens hypertexte
@app.template_filter('urlize')
def urlize_filter(s):
    return Markup(re.sub(r'(?<!\w)(/post/\d+)', r'<a href="\1">\1</a>', s))

if __name__ == '__main__':
    socketio.run(app)

from app.models import Donor

@app.context_processor
def inject_top_donor():
    top_donor = Donor.query.order_by(Donor.amount.desc()).first()
    return dict(top_donor=top_donor)
