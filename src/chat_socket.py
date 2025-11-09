from init_db import socketio, db
from flask_socketio import join_room, leave_room
from database import Message

from flask_login import current_user

@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('join')
def handle_join(data):
    if current_user.is_authenticated:
        leave_room(current_user.id)
        print(f"{current_user.id} left room {current_user.id}")
        username = data['username']
        join_room(str(username))
    else:
        return False


# @socketio.on('send_message')
# def handle_send_message(data):
#     if current_user.is_authenticated:
#       receiver = data['receiver']
#       text = data['text']

#       # Save message in DB
#       msg = Message(sender_id=current_user.id,
#                     recipient_id=receiver,
#                     content=text)
#       db.session.add(msg)
#       db.session.commit()

#       # Notify receiver instantly
#       emit('receive_message', {
#           'sender': current_user.id,
#           'text': text,
#           'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M')
#       }, room=receiver)

#       # Should probably send some message back to sender to validate that we received the message....
#     else:
#         return False