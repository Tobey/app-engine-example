from google.appengine.ext import db


class User(db.Model):
    email = db.StringProperty( indexed=True)
    password = db.StringProperty(indexed=True)


class Secret(db.Model):
    a_super_secret = db.StringProperty(indexed=False)
    index = db.StringProperty(index=True)