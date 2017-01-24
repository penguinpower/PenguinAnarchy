import bcrypt
from datetime import datetime, timedelta
import logging
import os
import smtplib
import sqlite3
import uuid

from flask import Flask
from flask import g
from flask import redirect, request, url_for, abort
from flask import render_template
app = Flask(__name__)

DATABASE = 'penguin.db'
SMTP_ACCOUNT = 'penguin@collison.net'
SMTP_ACCOUNT_PASSWORD = os.environ['PENGUIN_PASSWORD']
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/cow/<name>', methods=['GET', 'POST'])
def hello_cow(name):
    color = request.values.get('color')

    return render_template('cow.html', name=name, color=color)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        app.logger.debug('We need to log this person in.')
        login_data = request.form.to_dict()
        was_logged_in = log_in_user(login_data)
        if was_logged_in:
            return redirect(url_for(''))  # XXX
        else:
            abort()
    else:
        return render_template('login.html')


@app.route('/validate/<email>/<token>', methods=['GET'])
def validate():

    email = request.values.get('email')
    token = request.values.get('token')

    user = get_user_db_data(email)

    # handle no user account

    # check already validated

    # check token expired

    # check token matches


@app.route('/create_user', methods=['GET'])
def create_user():
    return render_template('create_user.html')


@app.route('/users/', methods=['POST'])
def users():
    if request.method == 'POST':
        user_data = request.form.to_dict()
        app.logger.debug(user_data)
        message = validate_new_user(user_data)
        if message:
            return redirect(url_for('login'))
        new_user = create_new_user(user_data)
        send_validation_email(new_user)
        return render_template('new_user_validation.html')


def log_in_user(login_data):

    encoded_email = login_data['email'].encode('utf-8')
    sql_get = """SELECT password FROM users WHERE email='{}'"""

    db = get_db()
    cur = db.cursor()
    cur.execute(sql_get.format(encoded_email))
    row = cur.fetchone()
    if not row:
        abort()
    stored_password = row[0]
    app.logger.debug(type(stored_password))
    encoded_password = login_data['password'].encode('utf-8')
    app.logger.debug(type(encoded_password))
    hashed_password = bcrypt.hashpw(encoded_password, str(stored_password))

    if stored_password == hashed_password:
        return True

    return False


def validate_new_user(user_data):

    # check if email already in use
    encoded_email = user_data['email'].encode('utf-8')
    db = get_db()
    cur = db.cursor()
    sql_get = """SELECT email, name FROM users WHERE email='{}'"""
    cur.execute(sql_get.format(encoded_email))
    row = cur.fetchone()
    app.logger.debug(row)

    # do we have a user?
    if row:
        app.logger.debug("FOO")
        return 'A user with that email address already exists.'


def create_new_user(user_data):

    # create unique token
    token = str(uuid.uuid4())

    # set expiration time
    tomorrow = datetime.utcnow() + timedelta(days=1)
    tomorrow = tomorrow.isoformat().split('.')[0]

    # encrypt password
    encoded_password = user_data['password'].encode('utf-8')
    hashed_password = bcrypt.hashpw(encoded_password, bcrypt.gensalt())

    sql = '''INSERT INTO users(email, name, password, validation_token, validation_token_expires)
             VALUES(?,?,?,?,?)'''

    try:
        db = get_db()
        cur = db.cursor()
    except Exception, ex:
        logging.exception(ex)
    app.logger.debug(user_data.get('email'))
    encoded_email = user_data['email'].encode('utf-8')
    encoded_name = user_data['name'].encode('utf-8')
    try:
        cur.execute(sql, (encoded_email, encoded_name, hashed_password,
                          token, tomorrow))
        db.commit()
    except Exception, ex:
        logging.exception(ex)

    # retrieve new user
    sql_get = '''SELECT email, name, validation_token FROM users WHERE id={}'''
    cur.execute(sql_get.format(cur.lastrowid))
    row = cur.fetchone()

    user = {
        'email': row[0].decode('utf-8'),
        'name': row[1].decode('utf-8'),
        'validation_token': row[2],
    }

    return user


def send_validation_email(new_user):

    email = new_user['email']
    name = new_user['name']

    server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
    server.set_debuglevel(True)
    server.login(SMTP_ACCOUNT, SMTP_ACCOUNT_PASSWORD)
 
    msg = ("Thanks for signing up with Penguin Anarchy!  In order "
           "to use your new account, please follow the link in this "
           "email.")
    server.sendmail(SMTP_ACCOUNT, email, msg)
    server.quit()


def get_user_db_data(email):

    encoded_email = email.encode('utf-8')
    db = get_db()
    cur = db.cursor()
    sql_get = """SELECT email, name, validated, validation_token,
                 validation_token_expires FROM users WHERE email='{}'"""
    cur.execute(sql_get.format(encoded_email))
    row = cur.fetchone()

    user = {
        'email': row[0].decode('utf-8'),
        'name': row[1].decode('utf-8'),
        'validated': row[2],
        'validation_token': row[3],
        'validation_token_expires': row[4]
    }

    return user
