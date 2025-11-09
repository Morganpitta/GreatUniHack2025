from init_db import app, db, socketio
import frontend

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app,debug=True, port=5000, host="0.0.0.0")