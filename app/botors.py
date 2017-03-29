from flask import Flask
from flask_pymongo import PyMongo
import config
from response import jsonify

app = Flask(__name__)
mongo = PyMongo(app)


@app.route('/', methods=['GET'])
def hello_world():
    notes = mongo.db.notes.find_one()
    return jsonify(notes)


if __name__ == '__main__':
    app.run(port=config.PORT, debug=config.DEBUG)