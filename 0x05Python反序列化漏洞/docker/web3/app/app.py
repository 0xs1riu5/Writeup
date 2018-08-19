import redis
import os
from flask import Flask,session
from flask_session import Session
app = Flask(__name__)
SESSION_TYPE = 'redis'
SESSION_PERMANENT = False
SESSION_USE_SIGNER = False
SESSION_KEY_PREFIX = 'session'
SESSION_REDIS = redis.Redis(host='127.0.0.1',port='6379')
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = 604800  # 7 days
app.config.from_object(__name__)
Session(app)


@app.route('/')
def hello_world():
    session['name']='test'
    return 'Hello World!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)


