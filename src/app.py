from flask import Flask, render_template, request, redirect, url_for, flash,session
# from flask_login import LoginManager , current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db as fbdb
from firebase_admin import db as fdb
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
        user = models.finduser(fbdb.reference("users").get(),username)
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

import models
@app.route('/register', methods=['GET', 'POST'])
def register():
    if "user" in session:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = models.makeuser(None,form.username.data,form.password.data)
        # userref = ref.child("users").push(user)
        # print(userref.key)
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
        password=models.finduser(fbdb.reference("users").get(),form.username.data)
        # user = User.query.filter_by(username=form.username.data).first()
        if password is None or not check_password_hash(password,form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        # login_user(user, remember=True)
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
    if "user" in session:
        return render_template('profile.html', title='Profile',user=session["user"])
    else:
        return redirect(url_for('login'))

@app.route('/conversations')
def conversations():
    loggedin=True

    user_ids = []
    converstion_list = get_as_list("conversations")
    for i in converstion_list:
        if i["user1"] == session["user"]:
            user_ids.append(i["user2"])
        elif i["user2"] == session["user"]:
            user_ids.append(i["user1"])

    user_ids = [{"username": i} for i in user_ids]

    return render_template('conversations.html', users=user_ids, title='Conversations',loggedin=loggedin)


@app.route('/new_conversation', methods=['POST'])
def new_conversation():
    username = request.form.get('username')
    if models.finduser(fbdb.reference("users").get(), username) is None:
        flash('User not found.', 'danger')
        return redirect(url_for('conversations'))

    if username == session["user"]:
        flash('You cannot start a conversation with yourself.', 'danger')
        return redirect(url_for('conversations'))
    
    for i in get_as_list("conversations"):
        if {i["user1"], i["user2"]} == {session["user"], username}:
            return redirect(url_for('chat', username=username))
    
    ref = fdb.reference("conversations")
    ref.push({"user1": session["user"], "user2": username, "id":str(uuid.uuid4())})

    return redirect(url_for('chat', username=username))



@app.route('/chat/<username>', methods=['GET', 'POST'])
def chat(username):
    partner = username
    current_user = session["user"]

    if partner == current_user:
        flash("You cannot chat with yourself.")
        return redirect(url_for('conversations'))
    
    converstion_list = get_as_list("conversations")
    conversation_id = [i for i in converstion_list if {i["user1"], i["user2"]} == {partner, current_user}][0]["id"]
    
    form = MessageForm()
    if form.validate_on_submit():
        print(conversation_id)
        chats_ref = fdb.reference("chats/" + conversation_id)
        chats_ref.push({"content": form.message.data, "sender_id": current_user, "timestamp": datetime.datetime.now().timestamp()})

        return redirect(url_for('chat', username=username))

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

    messages = chat_list

    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=partner, messages=messages,loggedin=True)

@app.route('/graph')
def graph():
    # Data to be visualized. You can replace this with data from a database, API, etc.
    data = [
        {"name": "UK", "color": "#D2691E"},
        {"name": "Germany", "color": "#FF69B4"},
        {"name": "Brazil", "color": "#1E90FF"},
        {"name": "Peru", "color": "#32CD32"}
    ]

    return render_template('graph.html', data=json.dumps(data))


def get_as_list(path):
    data = fdb.reference(path).get()

    if data is None:
        return None
    else:
        return list(fdb.reference(path).get().values())

if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()
    app.run(debug=True)