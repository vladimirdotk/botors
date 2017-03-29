import os
import binascii
from flask import Flask, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
import config
from response import jsonify

app = Flask(__name__)
mongo = PyMongo(app)
jwt = JWTManager(app)


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
        creds = get_credentials(username, password)
        if creds:
            return jsonify({'token': get_new_token(creds['_id'])}), 201

    return jsonify({'msg': 'Bad username or password!'}), 401


def get_credentials(username, password):
    """
    Get user's credentials
    :param str username: 
    :param str password: 
    :return dict|None: 
    """
    return mongo.db.users.find_one({'username': username, 'password': password})


def get_new_token(user_id):
    """
    Creates and returns user's token
    :param user_id: 
    :return: 
    """
    print(user_id)
    token = binascii.hexlify(os.urandom(24)).decode()
    mongo.db.tokens.insert_one({'user_id': user_id, 'token': token})
    return token

if __name__ == '__main__':
    app.run(port=config.PORT, debug=config.DEBUG)
