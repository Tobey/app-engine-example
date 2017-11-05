import json
import urllib

import webapp2

from models import User

from auth import jwt_secure
from auth import generate_jwt
from auth import set_header
from auth import email_and_password_required

JSON = 'application/json'


class MainPage(webapp2.RequestHandler):

    @set_header
    @jwt_secure
    def get(self, claims=None):
        self.response.headers['Content-Type'] = JSON
        self.response.write('This is a secure view \n'+ json.dumps(claims))


class AccountSignUp(webapp2.RequestHandler):

    @email_and_password_required
    def post(self, email=None, password=None):
        user = User.all().filter('email', email).get()
        if user:
            return self.response.write('email already exists')
        User(email=email, password=password).save()
        self.response.headers['Content-Type'] = JSON
        self.response.write( json.dumps({'token': urllib.quote_plus(generate_jwt(email))}))


class AccountSignIn(webapp2.RequestHandler):

    @email_and_password_required
    def post(self, email=None, password=None):
        user = User.all().filter('email', email).get()
        if user and user.verify_password(password):
            self.response.headers['Content-Type'] = JSON
            return self.response.write(json.dumps({'token': urllib.quote_plus(generate_jwt(email))}))
        self.response.set_status(405)
        return self.response.write('invalid login')

    @jwt_secure
    def put(self, claims=None):
        email = claims['user']
        new_email = self.request.get('email')
        user = User.all().filter('email', email).get()
        user.email = new_email
        user.save()


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/account/signup', AccountSignUp),
    ('/account/signin', AccountSignIn),
], debug=True)
