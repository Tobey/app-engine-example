# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
from models import User, Secret

from auth import jwt_secure
from auth import generate_jwt
from auth import email_and_password_required


class MainPage(webapp2.RequestHandler):

    @jwt_secure
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(Secret.get_secret('something'))


class AccountSignUp(webapp2.RequestHandler):

    @email_and_password_required
    def post(self, email=None, password=None):
        User(email=email, password=password).save()
        self.response.write(email)

class AccountSignIn(webapp2.RequestHandler):

    @email_and_password_required
    def post(self, email=None, password=None):
        user  = User.all().filter(email=email).get()
        if user and user.verify_password(password):
            return {'token': generate_jwt(email)}

        raise Exception('invalid login')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/account/signup', AccountSignUp),
    ('/account/signin', AccountSignIn),
    ('/api', MainPage),
], debug=True)
