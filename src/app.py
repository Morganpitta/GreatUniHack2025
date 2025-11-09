from flask import Flask, render_template, request, redirect, url_for, flash,session, jsonify
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
import random

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

    user_country = next(x for x in get_as_list("users") if x["username"] == session["user"])["location"]

    recommended_users = [x for x in get_as_list("users") if x["username"] not in user_ids and x["username"] != session["user"] and x["location"] != user_country]
    recommended_users = random.sample(recommended_users, 3)

    user_ids = [{"username": i} for i in user_ids]

    return render_template('conversations.html', users=user_ids, recommended_users=recommended_users, title='Conversations', loggedin=loggedin)

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
    location_dict = {}

    for i in get_as_list("users"):
        loc = i["location"].lower()
        if loc in location_dict:
            location_dict[loc] += 1
        else:
            location_dict[loc] = 1
    
    # colors = ["#D2691E", "#FF69B4", "#1E90FF", "#32CD32"]

    colors = [
        # --- Palette 1: Solar System Inspired ---
        "#97979F",  # Mercury (Rocky Gray)
        "#C3A171",  # Venus (Sulphuric Gold)
        "#4A90E2",  # Earth (Ocean Blue)
        "#3B5D38",  # Earth (Forest Green)
        "#A44322",  # Mars (Dusty Red)
        "#D39C7E",  # Jupiter (Stormy Bands)
        "#A49B72",  # Saturn (Pale Gold)
        "#9CCEDC",  # Uranus (Misty Cyan)
        "#054569",  # Neptune (Deep Blue)

        # --- Palette 2: Vibrant Sci-Fi ---
        "#FF69B4",  # Cyberpunk Pink
        "#00E5FF",  # Holographic Blue
        "#FF5B29",  # Giants Orange
        "#8A2BE2",  # Warp-Speed Purple
        "#3AD29F",  # Android Green
        "#FFDA24",  # Banana Yellow
        "#FF2F92",  # Unicorn Dust Pink

        # --- Palette 3: Gas Giant & Nebula Hues ---
        "#430D4B",  # Orion Nebula Purple
        "#081448",  # Galactic Forest Blue
        "#E6E6FA",  # Cosmic Lavender
        "#C72075",  # Magenta Dye
        "#1D1135",  # Deep Space Violet
        "#50F2CE",  # Turquoise Swirl
        "#9AEADD",  # Stardust Teal

        # --- Palette 4: Alien Worlds & Exoplanets ---
        "#76101E",  # Ruby Red Desert
        "#014760",  # Methane Sea Blue
        "#FFD700",  # Golden Supernova
        "#C874B2",  # Iridescent Lilac
        "#FF4500",  # Volcanic Orange
        "#A1CE3F",  # Acidic Green
        "#78CCe2",  # Crystal Spires Cyan
    ]

    data = [
        {
            "name": key,
            "size": location_dict[key] * 20, # Multiplier to make planets bigger
            "color": "#%06x" % random.randint(0, 0xFFFFFF) # Assign a random color
        } for key in location_dict
    ]

    print(data)

    # data = [
        # {"name": "india", "color": "#D2691E"},
        # {"name": "Germany", "color": "#FF69B4"},
        # {"name": "Brazil", "color": "#1E90FF"},
        # {"name": "Peru", "color": "#32CD32"}
    # ]

    return render_template('graph.html', chart_data=json.dumps(data), loggedin=("user" in session))

@app.route('/hover/<name>', methods=["GET"])
def handle_hover_planet_event(name):
    location = name
    response = gemini.generate_response(firestore.generate_prompt(gemini, location))
    return jsonify({'response': response})


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

# ### NEW SOCKET.IO HANDLERS FOR THE GRAPH PAGE ###
@socketio.on('join_graph')
def on_join_graph():
    """Adds the client to a room for graph viewers."""
    join_room('graph_viewers')

@socketio.on('leave_graph')
def on_leave_graph():
    """Removes the client from the graph viewers room."""
    leave_room('graph_viewers')


@socketio.on('send_message')
def handle_send_message_event(data):
    """
    Handles a client sending a message. Saves it to Firebase and broadcasts it.
    NOW ALSO broadcasts an activity event to the graph.
    """
    app.logger.info(f"Received message: {data}")

    conversation_id = data['conversation_id']
    message_content = data['message']
    sender_username = session['user']

    # Create the new message object
    new_message = {
        "content": message_content, 
        "sender_id": sender_username, 
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Save to Firebase
    chats_ref = fbdb.reference("chats/" + conversation_id)
    chats_ref.push(new_message)

    # Convert to vector embedding and save to Firestore
    sender_location_data = fbdb.reference(f"users/{sender_username}/location").get()
    if sender_location_data:
        embedding = gemini.embed_content(message_content, "RETRIEVAL_DOCUMENT")
        firestore.save_to_collection(sender_location_data, embedding, message_content)

    # Broadcast the chat message to the chat room
    socketio.emit('new_message', new_message, room=conversation_id)

    # --- NEW: BROADCAST ACTIVITY TO THE GRAPH ---
    # 1. Find the receiver
    conversations_data = get_as_list("conversations")
    receiver_username = None
    for conv in conversations_data:
        if conv.get("id") == conversation_id:
            if conv.get("user1") == sender_username:
                receiver_username = conv.get("user2")
            else:
                receiver_username = conv.get("user1")
            break
    
    # 2. Get receiver's location
    if receiver_username:
        receiver_location_data = fbdb.reference(f"users/{receiver_username}/location").get()
        
        # 3. If both locations exist, emit the event to the graph viewers
        if sender_location_data and receiver_location_data and sender_location_data.lower() != receiver_location_data.lower():
            activity_data = {
                'sender_location': sender_location_data.lower(),
                'receiver_location': receiver_location_data.lower()
            }
            socketio.emit('new_message_activity', activity_data, room='graph_viewers')

def get_as_list(path):
    data = fbdb.reference(path).get()
    if data is None:
        return []
    if isinstance(data, dict):
        return list(data.values())
    return data

if __name__ == '__main__':
    socketio.run(app, debug=True)