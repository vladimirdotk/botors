#!/usr/bin/env python3

import argparse
import sys
import pymongo
from flask_bcrypt import generate_password_hash
import app.config as config

parser = argparse.ArgumentParser()
parser.add_argument(
    '-u', '--user', type=str, help='username', required=True
)
parser.add_argument(
    '-p', '--password', type=str, help='password', required=True
)

args = parser.parse_args()

client = pymongo.MongoClient()
db = client.botors
collection = db.users

collection.create_index('username', unique=True)
print(generate_password_hash(args.password, config.BCRYPT_LOG_ROUNDS))
try:
    collection.insert_one(
        {
            'username': args.user,
            'password': generate_password_hash(args.password, config.BCRYPT_LOG_ROUNDS)
        }
    )
except pymongo.errors.DuplicateKeyError:
    sys.exit('Username exists! Try to choose another.')
