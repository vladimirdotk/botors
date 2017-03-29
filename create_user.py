#!/usr/bin/env python3

import argparse
import sys
import pymongo

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

try:
    collection.insert_one(
        {'username': args.user}, {'password': args.password}
    )
except pymongo.errors.DuplicateKeyError:
    sys.exit('Username exists! Try to choose another.')
