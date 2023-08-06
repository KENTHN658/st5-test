import os
from flask import Flask
from werkzeug.debug import DebuggedApplication
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail

app = Flask(__name__, static_folder='static')


# this DEBUG config here will be overridden by FLASK_DEBUG shell environment
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = '5f368334d63b951d072d7a0daa1a0ff0b8dda36e42a4b5d9'
app.config['JSON_AS_ASCII'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Google OAuth
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID", None)
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET", None)
app.config['GOOGLE_DISCOVERY_URL'] = os.getenv("GOOGLE_DISCOVERY_URL", None)

# Configure Facebook OAuth
app.config['FACEBOOK_CLIENT_ID'] = os.getenv("FACEBOOK_CLIENT_ID", None)
app.config['FACEBOOK_CLIENT_SECRET'] = os.getenv("FACEBOOK_CLIENT_SECRET", None)

# Configure GitHub OAuth
app.config['GITHUB_CLIENT_ID'] = os.getenv("GITHUB_CLIENT_ID", None)
app.config['GITHUB_CLIENT_SECRET'] = os.getenv("GITHUB_CLIENT_SECRET", None)

# Configure Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kitsadi_than@elearning.cmu.ac.th'
app.config['MAIL_PASSWORD'] = 'xalgtjvxhzjomzwb'

if app.debug:
    app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)
    
# Creating an SQLAlchemy instance
db = SQLAlchemy(app)
oauth = OAuth(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.login_view = 'diary_login'
login_manager.init_app(app)

from app import views # noqa