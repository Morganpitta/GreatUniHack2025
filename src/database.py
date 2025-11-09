
from werkzeug.security import generate_password_hash

import firebase_admin
from firebase_admin import credentials, db as fbdb
import dotenv
import os


dotenv.load_dotenv()

def makeuser(id,username,password):
    json={
        "id":id,
        "username":username,
        "password":generate_password_hash(password)
    }
    return json

def finduser(data,username):
    password = None
    if username in data.keys():
        password = data[username]["password"]
        print("found user")
    return password

def get_as_list(path):
    data = fbdb.reference(path).get()

    if data is None:
        return None
    else:
        return list(data.values())