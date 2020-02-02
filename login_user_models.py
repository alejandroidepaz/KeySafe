from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64
import onetimepass

class User(UserMixin):

    def __init__(self, username, email, password_hash=None, otp_secret=None):
        self.otp_secret = otp_secret
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.active = True

    def is_active(self):
        return self.active

    def get_id(self):
        return self.username

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/KeySafe:{0}?secret={1}&issuer=2FA-Demo'.format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

        
