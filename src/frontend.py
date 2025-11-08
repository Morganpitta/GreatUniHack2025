<<<<<<< HEAD
from init_db import app, login_manager, db, socketio, embedder, firestore
=======
from init_db import app, login_manager, db, gemini, firestore
>>>>>>> a1c94e2 (Add text content and prompt generation)
from database import User, Message

from sqlalchemy import or_
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import login_user, logout_user, current_user, login_required
from flask import render_template, request, redirect, url_for, flash
from flask_socketio import emit,leave_room,join_room

<<<<<<< HEAD:src/frontend.py
import chat_socket
=======
import firebase_admin
from firebase_admin import credentials, auth, db as fdb

import datetime
import json
import uuid

cred = credentials.Certificate("./space-mouse-4803e-firebase-adminsdk-fbsvc-98226ecde3.json") # <<< IMPORTANT: UPDATE THIS PATH & FILENAME

# Initialize the app with your project ID and database URL
# The database URL for your project is: https://space-mouse-4803e-default-rtdb.europe-west1.firebasedatabase.app
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://space-mouse-4803e-default-rtdb.europe-west1.firebasedatabase.app'
})

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
>>>>>>> fc1d9a7 (my changes):app.py


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
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
    if current_user.is_authenticated:
        return redirect(url_for('conversations'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=True)
        return redirect(url_for('index'))
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route('/conversations')
@login_required
def conversations():
    # Find all users the current user has had a conversation with
    # sent_messages = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id)
    # received_messages = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
    
    # user_ids = set([item[0] for item in sent_messages.all()] + [item[0] for item in received_messages.all()])
    user_ids = []

    converstion_list = get_as_list("conversations")
    for i in converstion_list:
        if i["user1"] == current_user.id:
            user_ids.append(i["user2"])
        elif i["user2"] == current_user.id:
            user_ids.append(i["user1"])

    print(converstion_list)

    user_ids = set(user_ids)

    users = User.query.filter(User.id.in_(user_ids)).all()


    
    return render_template('conversations.html', users=users, title='Conversations')

@app.route('/new_conversation', methods=['GET', 'POST'])
@login_required
def new_conversation():
<<<<<<< HEAD:src/frontend.py
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            if user.id == current_user.id:
                flash('You cannot start a conversation with yourself.', 'danger')
                return redirect(url_for('conversations'))
            return redirect(url_for('chat', username=user.username))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('conversations'))
    return render_template('new_conversation.html', title='New Conversation')
=======
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('conversations'))
>>>>>>> fc1d9a7 (my changes):app.py

    if user.id == current_user.id:
        flash('You cannot start a conversation with yourself.', 'danger')
        return redirect(url_for('conversations'))
    
    ref = fdb.reference("conversations")
    ref.push({"user1": current_user.id, "user2": user.id, "id":str(uuid.uuid4())})

    print("\n\nthis is registering\n")

    return redirect(url_for('chat', username=user.username))
        

@app.route('/chat/<username>', methods=['GET', 'POST'])
@login_required
def chat(username):
    partner = User.query.filter_by(username=username).first_or_404()
    if partner == current_user:
        flash("You cannot chat with yourself.")
        return redirect(url_for('conversations'))
    
    converstion_list = get_as_list("conversations")
    conversation_id = [i for i in converstion_list if {i["user1"], i["user2"]} == {partner.id, current_user.id}][0]["id"]
    
    form = MessageForm()
    if form.validate_on_submit():
<<<<<<< HEAD:src/frontend.py
        msg = Message(sender_id=current_user.id,
                      recipient_id=partner.id,
                      content=form.message.data)
        db.session.add(msg)
        db.session.commit()

        # save message as a vector embedding
        embedding = gemini.embed_content(form.message.data, "RETRIEVAL_DOCUMENT")
        firestore.save_to_collection("mars", embedding, form.message.data)



        print(f"broadcasting message {partner.id}, {current_user.id}")
        # Notify receiver instantly
        socketio.emit('receive_message', {
            'sender': current_user.id,
            'text': form.message.data,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
        }, to=str(partner.id))

        print("broadcasted")
    
=======
        chats_ref = fdb.reference("chats/" + conversation_id)
        chats_data = chats_ref.push({"content": form.message.data, "sender_id": current_user.id, "timestamp": datetime.datetime.now().timestamp()})

        # msg = Message(sender_id=current_user.id,
        #               recipient_id=partner.id,
        #               content=form.message.data)
        # db.session.add(msg)
        # db.session.commit()
>>>>>>> fc1d9a7 (my changes):app.py
        return redirect(url_for('chat', username=username))

    # messages = Message.query.filter(
    #     or_(
    #         (Message.sender_id == current_user.id) & (Message.recipient_id == partner.id),
    #         (Message.sender_id == partner.id) & (Message.recipient_id == current_user.id)
    #     )
    # ).order_by(Message.timestamp.asc()).all()

    # chats_ref = fdb.reference('chats/huqwhuqw3849')
    # chats_data = chats_ref.get()

    # print(chats_data)
    chat_list = []

    full_list = get_as_list("chats/" + conversation_id)
    if full_list == None:
        full_list = []

    for i in full_list:
        print(i)
        if "timestamp" in i:
            i["timestamp"] = datetime.datetime.fromtimestamp(float(i["timestamp"]))
        else:
            i["timestamp"] = datetime.datetime.fromtimestamp(0.0)

        chat_list.append(i)

    # print(chats_data)

    messages = chat_list

    # messages = [
    #     {"sender_id": 4, "content": "hey wassup", "timestamp": datetime.datetime(2025, 11, 8, 15, 37, 5)},
    #     {"sender_id": 3, "content": "hey wassup", "timestamp": datetime.datetime(2025, 11, 8, 15, 32, 6)},
    # ]

    # print(json.dumps(messages, indent=4))

    # Logic to fetch users for the sidebar
    sent_messages = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id)
    received_messages = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
    user_ids = set([item[0] for item in sent_messages.all()] + [item[0] for item in received_messages.all()])
    users = User.query.filter(User.id.in_(user_ids)).all()

<<<<<<< HEAD:src/frontend.py
    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=partner, messages=messages, users=users)
=======
def get_as_list(path):
    data = fdb.reference(path).get()

    if data is None:
        return None
    else:
        return list(fdb.reference(path).get().values())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


def get_first_match():
    pass

>>>>>>> fc1d9a7 (my changes):app.py
