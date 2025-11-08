import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from services import embeddings
from firebase_admin import credentials

# App initialization
cred = credentials.Certificate('/home/george/GreatUniHack/GreatUniHack2025/src/services/space-mouse-4803e-firebase-adminsdk-fbsvc-98226ecde3.json')
template_dir = os.path.abspath('../templates')
static_dir = os.path.abspath('../static')
print(template_dir)
app = Flask(__name__,template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

embedder = embeddings.Embedder("gemini-embedding-001")
firestore = embeddings.Firestore(cred)