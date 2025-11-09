from flask import Flask, render_template, request, redirect, url_for, flash,session
# from flask_login import LoginManager , current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, join_room, leave_room, emit

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
socketio = SocketIO(app)

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db as fbdb
import dotenv
import os
import uuid
import datetime
import json

dotenv.load_dotenv()
CRED=os.environ.get("CRED")
URL=os.environ.get("URL")

cred = credentials.Certificate(CRED)

firebase_admin.initialize_app(cred, {
    'databaseURL': URL
})

ref = fbdb.reference('/')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        users = fbdb.reference("users").get()
        if users:
            for user in users.values():
                if user['username'] == username.data:
                    raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

# Routes
@app.route('/')
def index():
    if "user" in session:
        return redirect(url_for('conversations'))
    return redirect(url_for('login'))

import models
@app.route('/register', methods=['GET', 'POST'])
def register():
    if "user" in session:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = {"username": form.username.data, "password": hashed_password}
        fbdb.reference("users/" + form.username.data).set(user)

        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user" in session:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user_data = fbdb.reference("users/" + form.username.data).get()
        if user_data is None or not check_password_hash(user_data['password'], form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        flash("Logged in!")
        session["user"] = form.username.data
        return redirect(url_for('index'))
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    session.pop("user", None)
    flash("Logged out!")
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if "user" in session:
        return render_template('profile.html', title='Profile', user=session["user"])
    else:
        return redirect(url_for('login'))

@app.route('/conversations')
def conversations():
    loggedin = True
    user_ids = []
    converstion_list = get_as_list("conversations")
    if converstion_list:
        for i in converstion_list:
            if i["user1"] == session["user"]:
                user_ids.append(i["user2"])
            elif i["user2"] == session["user"]:
                user_ids.append(i["user1"])

    user_ids = [{"username": i} for i in user_ids]

    return render_template('conversations.html', users=user_ids, title='Conversations', loggedin=loggedin)

@app.route('/new_conversation', methods=['POST'])
def new_conversation():
    username = request.form.get('username')
    if fbdb.reference("users/" + username).get() is None:
        flash('User not found.', 'danger')
        return redirect(url_for('conversations'))

    if username == session["user"]:
        flash('You cannot start a conversation with yourself.', 'danger')
        return redirect(url_for('conversations'))

    conversations_list = get_as_list("conversations")
    if conversations_list:
        for i in conversations_list:
            if {i["user1"], i["user2"]} == {session["user"], username}:
                return redirect(url_for('chat', username=username))

    ref = fbdb.reference("conversations")
    ref.push({"user1": session["user"], "user2": username, "id": str(uuid.uuid4())})

    return redirect(url_for('chat', username=username))

@app.route('/chat/<username>', methods=['GET', 'POST'])
def chat(username):
    partner = username
    current_user = session["user"]

    if partner == current_user:
        flash("You cannot chat with yourself.")
        return redirect(url_for('conversations'))

    converstion_list = get_as_list("conversations")
    if not converstion_list:
        return redirect(url_for('conversations'))
        
    conversation = [i for i in converstion_list if {i.get("user1"), i.get("user2")} == {partner, current_user}]
    if not conversation:
        # Handle case where conversation doesn't exist
        return redirect(url_for('new_conversation', username=partner))
    conversation_id = conversation[0]["id"]


    form = MessageForm()
    if form.validate_on_submit():
        chats_ref = fbdb.reference("chats/" + conversation_id)
        new_message = {"content": form.message.data, "sender_id": current_user, "timestamp": datetime.datetime.now().isoformat()}
        chats_ref.push(new_message)

        # Emit the new message to the room
        socketio.emit('new_message', new_message, room=conversation_id)

        return redirect(url_for('chat', username=username))

    chat_list = []
    full_list = get_as_list("chats/" + conversation_id)
    if full_list:
        for i in full_list:
            if "timestamp" in i:
                try:
                    i["timestamp"] = datetime.datetime.fromisoformat(i["timestamp"])
                except:
                     i["timestamp"] = datetime.datetime.fromtimestamp(float(i["timestamp"]))
            else:
                i["timestamp"] = datetime.datetime.now()
            chat_list.append(i)

    messages = sorted(chat_list, key=lambda x: x['timestamp'])

    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=partner, messages=messages, loggedin=True, conversation_id=conversation_id)

# Socket.IO event handlers
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)

def get_as_list(path):
    data = fbdb.reference(path).get()
    if data is None:
        return []
    if isinstance(data, dict):
        return list(data.values())
    return data

if __name__ == '__main__':
    socketio.run(app, debug=True)