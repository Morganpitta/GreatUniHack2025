import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from services import gemini, firestore
from firebase_admin import credentials
import firebase_admin

# App initialization
template_dir = os.path.abspath('../templates')
static_dir = os.path.abspath('../static')
print(template_dir)
app = Flask(__name__,template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the app only if it hasn't been initialized yet.
try:
    app = firebase_admin.get_app()
except ValueError as e:
    cred = credentials.Certificate('services/cert.json')
    firebase_admin.initialize_app(cred)

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, manage_session=False)

gemini = gemini.Gemini("gemini-embedding-001")
firestore = firestore.Firestore()
