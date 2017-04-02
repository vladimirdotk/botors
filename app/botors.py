import os
import binascii
from flask import Flask, request, abort
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import config as config
from response import jsonify
from functools import wraps
from bson.objectid import ObjectId

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
        token = get_token_from_request(request)
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


@app.route('/notes/<note_id>', methods=['GET'])
@login_required
def get_notes(note_id):
    """
    Returns user's note
    :param str note_id: 
    :return: 
    """
    data = mongo.db.notes.find_one({
        '_id': ObjectId(note_id),
        'user_id': get_user_id_by_request(request)
    }, {'user_id': 0})

    return jsonify(data) if data else jsonify({'msg': 'Not found'}), 404


@app.route('/notes', methods=['POST'])
@login_required
def add_note():
    """
    Adds note to db
    :return: 
    """
    json_request = request.get_json()
    if json_request and set(json_request.keys()).issubset(set(NOTE_FIELDS)):
        data = mongo.db.notes.insert_one({
            **json_request,
            **{'user_id': get_user_id_by_request(request)}
        })
        return jsonify({'_id': data.inserted_id}), 201

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


def get_user_id_by_request(http_request):
    """
    Returns user_id by request
    :param Request http_request: 
    :return: 
    """
    token = get_token_from_request(http_request)

    return get_user_id_by_token(token)


def get_user_id_by_token(token):
    """
    Returns user_id by token
    :param str token: 
    :return str|None: 
    """
    data = mongo.db.tokens.find_one({'token': token})

    return data.get('user_id') if data else None


def get_token_from_request(http_request):
    """
    Returns token from request
    :param Request http_request: 
    :return str: 
    """

    return http_request.headers.get('token')


if __name__ == '__main__':
    app.run(port=config.PORT, debug=config.DEBUG)
