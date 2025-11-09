from init_db import app, login_manager, db, socketio, embedder, firestore
from database import User, Message

from sqlalchemy import or_
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import login_user, logout_user, current_user, login_required
from flask import render_template, request, redirect, url_for, flash
from flask_socketio import emit,leave_room,join_room

import chat_socket


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
    sent_messages = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id)
    received_messages = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
    
    user_ids = set([item[0] for item in sent_messages.all()] + [item[0] for item in received_messages.all()])
    
    users = User.query.filter(User.id.in_(user_ids)).all()
    
    return render_template('conversations.html', users=users, title='Conversations')

@app.route('/new_conversation', methods=['GET', 'POST'])
@login_required
def new_conversation():
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

@app.route('/chat/<username>', methods=['GET', 'POST'])
@login_required
def chat(username):
    partner = User.query.filter_by(username=username).first_or_404()
    if partner == current_user:
        flash("You cannot chat with yourself.")
        return redirect(url_for('conversations'))

    form = MessageForm()
    if form.validate_on_submit():
        msg = Message(sender_id=current_user.id,
                      recipient_id=partner.id,
                      content=form.message.data)
        db.session.add(msg)
        db.session.commit()

        # save message as a vector embedding
        embedding = embedder.embed_content(form.message.data, "RETRIEVAL_DOCUMENT")
        firestore.save_to_collection("mars", embedding)

        # Notify receiver instantly
        socketio.emit('receive_message', {
            'sender': current_user.id,
            'text': form.message.data,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
        }, to=str(partner.id))
    
        return redirect(url_for('chat', username=username))

    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == partner.id),
            (Message.sender_id == partner.id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    # Logic to fetch users for the sidebar
    sent_messages = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id)
    received_messages = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
    user_ids = set([item[0] for item in sent_messages.all()] + [item[0] for item in received_messages.all()])
    users = User.query.filter(User.id.in_(user_ids)).all()

    return render_template('chat.html', title=f'Chat with {username}',
                           form=form, partner=partner, messages=messages, users=users)