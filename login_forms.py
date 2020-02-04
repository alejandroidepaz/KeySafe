from wtforms import StringField, PasswordField, SubmitField, validators
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo
from flask_wtf import FlaskForm
import re

import mongodb_config as cfg
from pymongo import MongoClient

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators = [DataRequired(), Length(min = 8, max = 35)], render_kw={"placeholder": "Password"})
    token = StringField('Token', validators=[DataRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Your 6-Digit Token"})
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired(), Length(min = 5, max = 35)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
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

    def validate_password(self, password):

        error_messages = {

            "length": "Minimum Length of 8 | ",
            "digit": "Minimum 1 Number | ",
            "uppercase": "Minimum 1 Uppercase Letter | ",
            "lowercase": "Minimum 1 Lowercase Letter | ",
            "special_chars": "Minimum 1 Special Character | "
    
        }
        password = password.data

        length_check = len(password) > 7

        digit_check = re.search(r"[0-9]", password) is not None 

        uppercase_check = re.search(r"[A-Z]", password) is not None

        lowercase_check = re.search(r"[a-z]", password) is not None

        special_chars_check = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is not None

        password_verified = length_check and digit_check and uppercase_check and lowercase_check and special_chars_check

        results_dict = {

            "length": length_check,
            "digit": digit_check,
            "uppercase": uppercase_check,
            "lowercase": lowercase_check,
            "special_chars": special_chars_check
            
        }

        if not password_verified:
            error_message = ""
            for key in results_dict.keys():
                if not results_dict[key]:
                    error_message += error_messages[key]
            
            raise ValidationError("Password Failed the following criteria:\n" + error_message)