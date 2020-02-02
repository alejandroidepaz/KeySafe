from wtforms import StringField, PasswordField, SubmitField, validators
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo
from flask_wtf import FlaskForm

import mongodb_config as cfg
from pymongo import MongoClient

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators = [DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Password"})
    token = StringField('Token', validators=[DataRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Your 6-Digit Token"})
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Password"})
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        client = MongoClient("mongodb+srv://"+ cfg.mongodb["username"] + ":" + cfg.mongodb["password"] + "@" + cfg.mongodb["host"])
        userdb = client.KeySafe # the DB name is Users
        user = userdb.user_login_credentials.find_one({"username": username.data})
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        client = MongoClient("mongodb+srv://"+ cfg.mongodb["username"] + ":" + cfg.mongodb["password"] + "@" + cfg.mongodb["host"])
        userdb = client.KeySafe # the DB name is Users
        user = userdb.user_login_credentials.find_one({"email": email.data})
        if user is not None:
            raise ValidationError('Please use a different email address.')