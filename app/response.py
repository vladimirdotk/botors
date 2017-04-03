import json
import datetime
from bson.objectid import ObjectId
from flask import Response


class MongoJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif isinstance(obj, ObjectId):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


def jsonify(data):
    return json_response(dumps(data))


def dumps(data):
    return json.dumps(data, cls=MongoJsonEncoder)


def json_response(data):
    return Response(data, mimetype='application/json')
