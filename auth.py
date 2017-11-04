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
    auth = headers.get(
        'HTTP_AUTHORIZATION',
        ''
    )

    try:
        standard, token = auth.split(' ')
    except:
        standard = None
    if standard != 'Bearer':
        raise JWTError('Authorization header must be "Bearer {Token}"')
    return token


def verify_jwt(headers):
    token = get_token_from_header(
        headers
    )
    payload = jwt.decode(
        token,
        Secret.get_secret('jwt'),
        verify=True
    )

    return payload


def generate_jwt(email):
    claims = {
        'exp': 'never',
        'iss': 'toby',
        'aud': 'hopster',
        'user': email
    }
    token = jwt.encode(payload=claims, key=Secret.get_secret('jwt'), algorithm='RS512')
    return token, claims


def jwt_secure(f):
    '''A webapp2.RequestHandler method decorator'''

    def wrapper(self, *args, **kwargs):
        try:
            verify_jwt(self.request.headers)
        except JWTError as e:
            return self.response.write(e)
        return f(self, *args, **kwargs)
    return wrapper


def email_and_password_required(f):
    '''A webapp2.RequestHandler method decorator'''

    def wrapper(self, *args, **kwargs):
        email = self.request.get('email')
        password = self.request.get('password')
        if not email and password:
            raise Exception('email and password required')
        return f(self, *args, email=email, password=password, **kwargs)
    return wrapper
