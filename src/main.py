from init_db import app, db
import frontend
from services import embeddings

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)