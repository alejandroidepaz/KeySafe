import flask, sys
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_bootstrap import Bootstrap
from werkzeug.urls import url_parse
from login_user_models import *
from login_forms import *
import pyotp
import onetimepass as otp
import io
import pyqrcode

import os
from pymongo import MongoClient
import pymongo
import mongodb_config as cfg
import keyring


app = Flask(__name__)

# gets the keyring for the secret key, which is stored by the system's 
# secure storage eg macos keychain or windows credential locker
app.secret_key = keyring.get_password("system", "secret_key")



login = LoginManager(app)
login.init_app(app)
bootstrap = Bootstrap(app)

# reCAPTCHA API info
app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']= '6Lcm2NUUAAAAAL2GOOOkRV2WBELTUr0lX40D4DG7'
app.config['RECAPTCHA_PRIVATE_KEY']= keyring.get_password("system","recapthca_priv")
app.config['RECAPTCHA_OPTIONS'] = {'theme':'white'}

# Establish connection with MongoClient and iniitalize DataBase
client = MongoClient("mongodb+srv://"+ cfg.mongodb["username"] + ":" + cfg.mongodb["password"] + "@" + cfg.mongodb["host"])
userdb = client.KeySafe # the DB name is Whats_Kraken

@app.errorhandler(404)
def page_not_found(error):
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404

@login.user_loader
def load_user(username):
    
    user = userdb.user_login_credentials.find_one({"username": username})

    if user is not None:
        found_user = User(user["username"], user["email"], password_hash=user['password'], otp_secret = user["otp_secret"])
        return found_user

    return user

login.login_view='/login'


# BEGIN LOGIN & REGISTRATION ENDPOINTS 

@app.route("/login", methods=["GET", "POST"])
def login_page():
        if current_user.is_authenticated:
                return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
                user = load_user(str(form.username.data))
                
                if user is None or not user.check_password(form.password.data) or not user.verify_totp(form.token.data):
                        flash('Invalid username or password')
                        return redirect(url_for('login_page'))
                
                login_user(user)
                next_page = request.args.get('next')
                if not next_page or url_parse(next_page).netloc != '':
                        next_page = url_for('index')
                return redirect(next_page)

        return render_template('login.html', title='Sign In', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
        if current_user.is_authenticated:
                return redirect(url_for('index'))

        form = RegistrationForm()
        if form.validate_on_submit():

                user = User(form.username.data, form.email.data)
                user.set_password(form.password.data)

                userdb.user_login_credentials.insert_one({"username":user.username, "password":user.password_hash, "email":user.email, "otp_secret":user.otp_secret})
                
                # redirect to the two-factor auth page, passing username in session
                session['username'] = user.username
                return redirect(url_for('two_factor_setup'))

        return render_template('registration.html', title='Register', form=form)

@app.route("/two_factor_setup")
def two_factor_setup():

    if 'username' not in session:
        return redirect(url_for('login'))

    user = load_user(str(session["username"]))
    if user is None:
        return redirect(url_for('register'))

    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two_factor_setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qrcode():

    if 'username' not in session:
        redirect(url_for("register"))

    user = load_user(str(session["username"]))
    if user is None:
        redirect(url_for("register"))

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = io.BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route("/logout")
def logout():
        logout_user()
        return redirect(url_for('login_page'))


@app.route("/")
@app.route("/index")
@login_required
def index():
        return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)