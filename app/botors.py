import os
import binascii
from flask import Flask, request, abort
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import config as config
from response import jsonify
from functools import wraps

app = Flask(__name__)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

NOTE_FIELDS = ['header', 'body']


def login_required(fn):
    """
    Check auth decorator
    :param callable fn: 
    :return callable: 
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('token')
        if token and mongo.db.tokens.find_one({'token': token}):
            return fn(*args, **kwargs)
        abort(401)
    return wrapper


@app.route('/login', methods=['POST'])
def login():
    """
    Logs the user in
    :return: 
    """
    json_request = request.get_json()
    if json_request:
        username = json_request.get('username', None)
        password = json_request.get('password', None)
        user_data = get_user_data(username)
        if user_data and check_password(username, password):
            return jsonify({'token': get_new_token(user_data['_id'])}), 201

    return jsonify({'msg': 'Bad username or password!'}), 401


@app.route('/notes', methods=['POST'])
@login_required
def add_note():
    json_request = request.get_json()
    if json_request and set(json_request.keys()).issubset(set(NOTE_FIELDS)):
        data = mongo.db.notes.insert_one(json_request)
        return jsonify({'id': data.inserted_id}), 201

    return jsonify({'msg': 'Bad request'}), 400


def get_user_data(username):
    """
    Returns user's data
    :param username: 
    :return dict: 
    """
    return mongo.db.users.find_one({'username': username})


def check_password(username, password):
    """
    Check user's password
    :param str username: 
    :param str password: 
    :return bool: 
    """

    data = mongo.db.users.find_one({
        'username': username
    })

    return bcrypt.check_password_hash(data['password'], password)


def get_new_token(user_id):
    """
    Creates and returns user's token
    :param user_id: 
    :return: 
    """
    token = binascii.hexlify(os.urandom(24)).decode()
    mongo.db.tokens.insert_one({'user_id': user_id, 'token': token})
    return token


if __name__ == '__main__':
    app.run(port=config.PORT, debug=config.DEBUG)
