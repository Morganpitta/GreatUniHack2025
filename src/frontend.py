from init_db import app, socketio, embedder, firestore

from sqlalchemy import or_
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
from firebase_admin import db as fbdb
import uuid
import datetime

import chat_socket
import database


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = database.finduser(fbdb.reference("users").get(),username)
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
    if "user" in session:
        return redirect(url_for('conversations'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if "user" in session:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = database.makeuser(None, form.username.data,form.password.data)

        fbdb.reference("users/"+form.username.data).set(user)

        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user" in session:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        users = fbdb.reference("users").get()
        password = database.finduser(users,form.username.data)

        if password is None or not check_password_hash(password,form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        flash("Logged in!")
        session["user"]=form.username.data
        return redirect(url_for('index'))
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    session.pop("user",None)
    flash("Logged out!")
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if "user" not in session: 
      return redirect(url_for('login')) 
    return render_template('profile.html', title='Profile')

@app.route('/conversations')
def conversations():
    if "user" not in session: 
      return redirect(url_for('login')) 

    # Find all users the current user has had a conversation with
    user_ids = []
    conversation_list = database.get_as_list("conversations")
    for i in conversation_list:
        if i["user1"] == session["user"]:
            user_ids.append(i["user2"])
        elif i["user2"] == session["user"]:
            user_ids.append(i["user1"])
      
    return render_template('conversations.html', users=user_ids, title='Conversations')

@app.route('/new_conversation', methods=['GET', 'POST'])
def new_conversation():
    if "user" not in session: 
      return redirect(url_for('login')) 

    if request.method == 'POST':
        username = request.form.get('username')

        if database.finduser(fbdb.reference("users").get(),username) is None:
            flash("User not found.", "danger")
            return redirect(url_for('conversations'))
        
        if username == session["user"]:
            flash("you cannot start a conversation with yourself.","danger")
            return redirect(url_for('conversations'))
        
        for i in get_as_list("conversations"):
            if {i["user1"],i["user2"]} == {session["user"],username}:
                return redirect(url_for("chat",username=username))
        
        #No conversation found, lets create one

        ref = fbdb.reference("conversation")
        ref.push({"user1":session["user"],"user2":username,"id":str(uuid.uuid4())})

        return redirect(url_for("chat",username=username))

    return render_template('new_conversation.html', title='New Conversation')

@app.route('/chat/<username>', methods=['GET', 'POST'])
def chat(username):
    if "user" not in session: 
      return redirect(url_for('login')) 

    current_user = session["user"]

    if username == current_user:
        flash("You cannot chat with yourself.")
        return redirect(url_for('conversations'))
    
    conversation_list = get_as_list("conversations")
    conversation_id = [i for i in conversation_list if {i["user1"],i["users2"]} == {username,current_user}][0]["id"]

    form = MessageForm()
    if form.validate_on_submit():
        timestamp=datetime.datetime.now().timestamp()
        chats_ref = fbdb.reference("chats/"+conversation_id)
        chats_ref.push({"content":form.message.data, "sender_id":current_user,"timestamp":timestamp})

        # save message as a vector embedding
        embedding = embedder.embed_content(form.message.data, "RETRIEVAL_DOCUMENT")
        firestore.save_to_collection("mars", embedding)

        # Notify receiver instantly
        socketio.emit('receive_message', {
            'sender': current_user,
            'text': form.message.data,
            'timestamp': timestamp
        }, to=str(username))
    
        return redirect(url_for('chat', username=username))

    chat_list = get_as_list("chats/"+conversation_id)
    if chat_list == None:
        chat_list = []

    # Find all users the current user has had a conversation with
    user_ids = []
    conversation_list = database.get_as_list("conversations")
    for i in conversation_list:
        if i["user1"] == session["user"]:
            user_ids.append(i["user2"])
        elif i["user2"] == session["user"]:
            user_ids.append(i["user1"])

    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=username, messages=chat_list, users=user_ids)