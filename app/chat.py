# app/chat.py

from flask_socketio import SocketIO, emit
from app import app, db
from app.models import User, Message

socketio = SocketIO(app)

@socketio.on('message')
def handleMessage(data):
    msg_type = data.get('type', 'text')
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']

    if msg_type == 'text':
        content = data['msg']
    elif msg_type == 'image':
        content = data['msg']  # The image data URL

    # Save the message in the database
    message = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
    db.session.add(message)
    db.session.commit()

    # Send the message to the receiver
    emit('message', {
        'content': content,
        'type': msg_type,
        'sender_id': sender_id,
        'receiver_id': receiver_id
    }, to=receiver_id)
