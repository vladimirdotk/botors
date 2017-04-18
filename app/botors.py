import os
import binascii
from flask import Flask, request, redirect, abort
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


@app.route('/notes', methods=['GET'])
@login_required
def get_notes():
    """
    Returns user notes
    :return: 
    """
    data = mongo.db.notes.find({
        'user_id': get_user_id_by_request(request)
    }, {'user_id': 0})

    if data.count() > 0:
        return jsonify([document for document in data])

    return jsonify({'msg': 'Not found'}), 404


@app.route('/notes/<note_id>', methods=['GET'])
@login_required
def get_note(note_id):
    """
    Returns user's note
    :param str note_id: 
    :return: 
    """
    data = mongo.db.notes.find_one({
        '_id': ObjectId(note_id),
        'user_id': get_user_id_by_request(request)
    }, {'user_id': 0})

    if data:
        return jsonify(data)

    return jsonify({'msg': 'Not found'}), 404


@app.route('/notes', methods=['POST'])
@login_required
def add_note():
    """
    Adds note to db
    :return: 
    """
    json_request = request.get_json()
    if json_request and is_valid_note_fields(json_request.keys()):
        data = mongo.db.notes.insert_one({
            **json_request,
            **{'user_id': get_user_id_by_request(request)}
        })
        return jsonify({'_id': data.inserted_id}), 201

    return jsonify({'msg': 'Bad request'}), 400


@app.route('/notes/<note_id>', methods=['PUT'])
@login_required
def edit_note(note_id):
    """
    Edit note
    :param str note_id: 
    :return: 
    """
    json_request = request.get_json()
    if json_request and is_valid_note_fields(json_request.keys()):
        result = mongo.db.notes.update_one({
            '_id': ObjectId(note_id),
            'user_id': get_user_id_by_request(request)
        }, {
            '$set': json_request
        }, upsert=False)

        if result.matched_count > 0:
            return redirect('/notes/{}'.format(note_id))
        else:
            return jsonify({'msg': 'Not found'}), 404

    return jsonify({'msg': 'Bad request'}), 400


@app.route('/notes/<note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    """
    Delete note
    :param str note_id: 
    :return: 
    """

    data = mongo.db.notes.delete_one({
        '_id': ObjectId(note_id),
        'user_id': get_user_id_by_request(request)
    })

    if data.deleted_count > 0:
        return jsonify({}), 204

    return jsonify({'msg': 'Bad request'}), 400


@app.route('/notes/search', methods=['POST'])
@login_required
def search_note():
    """
    Search notes
    :return: 
    """
    search_data = request.get_json().get('text')

    if search_data:
        search_data_query = {
            '$regex': search_data,
            '$options': 'i'
        }
        result = mongo.db.notes.find({
            '$or': [
                {'header': search_data_query},
                {'body': search_data_query}
            ],
            'user_id': get_user_id_by_request(request)
        })

        if result.count() > 0:
            return jsonify([document for document in result])

    return jsonify({'msg': 'Not found'}), 404


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


def is_valid_note_fields(request_fields):
    """
    Validate note fields
    :param list request_fields: 
    :return: 
    """
    return set(request_fields).issubset(set(NOTE_FIELDS))


if __name__ == '__main__':
    app.run(port=config.PORT, debug=config.DEBUG)
