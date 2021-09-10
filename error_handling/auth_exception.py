from werkzeug.exceptions import HTTPException
from flask import Response


class AuthException(HTTPException):
    def __init__(self, message):
        super().__init__(message, Response(message, 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}))
