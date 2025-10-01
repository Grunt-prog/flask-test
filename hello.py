# Shamelessly copied from http://flask.pocoo.org/docs/quickstart/hihihihi

from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!
