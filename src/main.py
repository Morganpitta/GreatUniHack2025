from init_db import app, socketio
import frontend

if __name__ == '__main__':
    socketio.run(app,debug=True, port=5000, host="0.0.0.0")