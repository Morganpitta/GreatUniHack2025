from flask import Flask, render_template, request, redirect, url_for, flash,session
# from flask_login import LoginManager , current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, join_room, leave_room, emit
from services import gemini, firestore

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
import models # Re-added this import

dotenv.load_dotenv()
CRED=os.environ.get("CRED")
URL=os.environ.get("URL")

cred = credentials.Certificate(CRED)

try:
    app = firebase_admin.get_app()
except ValueError as e:
    cred = credentials.Certificate(CRED)
    firebase_admin.initialize_app(cred, {
        'databaseURL': URL
    })


ref = fbdb.reference('/')

gemini = gemini.Gemini("gemini-embedding-001")
firestore = firestore.Firestore()

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    location = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        # Assuming you have a models.finduser function
        users = fbdb.reference("users").get()
        if users and models.finduser(users, username.data):
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
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/home')
def home():
    return render_template('home.html', title='Home',loggedin=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if "user" in session:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Using the direct hashing method from your updated code
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = {"username": form.username.data, "password": hashed_password,"location":form.location.data}
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
        if user_data is None or not check_password_hash(user_data.get('password'), form.password.data):
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
        location = fbdb.reference("users/" + session["user"]).get().get("location")
        if location is None:
            location = "No location given"
        return render_template('profile.html', title='Profile', user=session["user"],location=location,loggedin=True)
    else:
        return redirect(url_for('login'))

@app.route('/conversations')
def conversations():
    loggedin = True
    user_ids = []
    converstion_list = get_as_list("conversations")
    if converstion_list:
        for i in converstion_list:
            if i.get("user1") == session["user"]:
                user_ids.append(i.get("user2"))
            elif i.get("user2") == session["user"]:
                user_ids.append(i.get("user1"))

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
            if {i.get("user1"), i.get("user2")} == {session["user"], username}:
                return redirect(url_for('chat', username=username))

    ref = fbdb.reference("conversations")
    ref.push({"user1": session["user"], "user2": username, "id": str(uuid.uuid4())})

    return redirect(url_for('chat', username=username))



@app.route('/chat/<username>', methods=['GET']) # REMOVED 'POST' from methods
def chat(username):
    # This route is now ONLY for loading the chat page initially.
    # The form submission logic is removed from here.
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
        return redirect(url_for('new_conversation', username=partner))
    conversation_id = conversation[0]["id"]

    form = MessageForm() # The form is still needed for the template

    chat_list = []
    full_list = get_as_list("chats/" + conversation_id)
    if full_list:
        for i in full_list:
            if "timestamp" in i:
                try:
                    i["timestamp"] = datetime.datetime.fromisoformat(i["timestamp"])
                except (ValueError, TypeError):
                    i["timestamp"] = datetime.datetime.fromtimestamp(float(i["timestamp"]))
            else:
                i["timestamp"] = datetime.datetime.now()
            chat_list.append(i)

    messages = sorted(chat_list, key=lambda x: x.get('timestamp'))

    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=partner, messages=messages, loggedin=True, conversation_id=conversation_id)


# Re-added the /graph route
@app.route('/graph')
def graph():
    # Data to be visualized. You can replace this with data from a database, API, etc.
    data = [
        {"name": "UK", "color": "#D2691E"},
        {"name": "Germany", "color": "#FF69B4"},
        {"name": "Brazil", "color": "#1E90FF"},
        {"name": "Peru", "color": "#32CD32"}
    ]

    return render_template('graph.html', chart_data=json.dumps(data))

@app.route('/hover/<name>',methods=["POST","GET"])
def handle_hover_planet_event(name):
    location=name
    response = gemini.generate_response(firestore.generate_prompt(gemini, location))
    print(response)
    return render_template('tourism_popup.html', location=location, response=response)


@socketio.on('send_message')
def handle_send_message_event(data):
    """
    Handles a client sending a message. Saves it to Firestore and broadcasts it.
    """
    app.logger.info(f"Received message: {data}")

    conversation_id = data['conversation_id']
    message_content = data['message']
    sender = session['user']

    # Create the new message object
    new_message = {
        "content": message_content, 
        "sender_id": sender, 
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Save to Firebase
    chats_ref = fbdb.reference("chats/" + conversation_id)
    chats_ref.push(new_message)

    # Convert to vector embedding and save to Firestore
    location = fbdb.reference("users/" + sender).get().get("location") 
    embedding = gemini.embed_content(message_content, "RETRIEVAL_DOCUMENT")
    firestore.save_to_collection(location, embedding, message_content)

    # Broadcast the message to all clients in the room (including the sender)
    socketio.emit('new_message', new_message, room=conversation_id)

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