import hmac
import base64
import hashlib

from google.appengine.ext import db


from utils import simple_cache


class User(db.Model):
    email = db.EmailProperty( indexed=True)
    password = db.StringProperty(indexed=True)

    @staticmethod
    def hash_with_secret(string, secret):
        hashed_password = hmac.new(
            str(string),
            msg=str(secret),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(hashed_password).decode()

    def verify_password(self, password):
        return self.password == self.hash_with_secret(password, Secret.get_secret('password'))

    def put(self, **kwargs):
        self.password = self.hash_with_secret(self.password, Secret.get_secret('password'))
        super(User, self).put(**kwargs)

    save = put


class Secret(db.Model):
    a_super_secret = db.StringProperty(indexed=False)
    index = db.StringProperty(indexed=True)

    @staticmethod
    @simple_cache
    def get_secret(index):
        secret = Secret.all().filter('index', index).get()
        return secret.a_super_secret
