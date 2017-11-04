import jwt
try:
    from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm
    jwt.register_algorithm('ES256', ECAlgorithm(ECAlgorithm.SHA256)) # Legacy encryption for Google app Engine
except BaseException:
    pass  # Cpython supported by this system

from models import Secret


class JWTError(Exception):
    pass


def get_token_from_header(headers):
    auth = headers.get('Authorization', '')
    try:
        standard, token = auth.split(' ')
    except:
        standard = token = None
    if standard != 'Bearer':
        raise JWTError('Authorization header must be "Bearer {Token}"')
    return token


def verify_jwt(headers):
    token = get_token_from_header(
        headers
    )
    try:
        payload = jwt.decode(
            token,
            Secret.get_secret('jwt'),
            verify=True
        )
    except:
        raise JWTError('Invalid Token')

    return payload


def generate_jwt(email):
    claims = {
        'exp': 'never',
        'iss': 'toby',
        'aud': 'hopster',
        'user': email
    }
    token = jwt.encode(payload=claims, key=Secret.get_secret('jwt'))
    return token, claims


def jwt_secure(f):
    '''A webapp2.RequestHandler method decorator'''

    def wrapper(self, *args, **kwargs):
        try:
            claims = verify_jwt(self.request.headers)
        except JWTError as e:
            return self.response.write(e)
        return f(self, *args, claims=claims, **kwargs)
    return wrapper


def email_and_password_required(f):
    '''A webapp2.RequestHandler method decorator'''

    def wrapper(self, *args, **kwargs):
        email = self.request.get('email')
        password = self.request.get('password')
        if not email or not password:
            return self.response.write('email and password are required')
        return f(self, *args, email=email, password=password, **kwargs)
    return wrapper


def set_header(f):
    def wrapper(self, *args, **kwargs):
        auth = self.request.get('authorization')
        if auth:
            self.request.headers['Authorization'] = 'Bearer ' + auth
        return f(self, *args, **kwargs)
    return wrapper