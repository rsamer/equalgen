from flask import request, jsonify, current_app
from flask_basicauth import BasicAuth
from functools import wraps
import logging


_logger = logging.getLogger(__name__)


class BcryptBasicAuth(BasicAuth):
    def __init__(self, app=None, bcrypt=None):
        super().__init__(app)
        self.bcrypt = bcrypt

    def check_credentials(self, username, password):
        correct_username = current_app.config['BASIC_AUTH_USERNAME']
        correct_password = current_app.config['BASIC_AUTH_PASSWORD']
        return username == correct_username and self.bcrypt.check_password_hash(correct_password, password)


def authentication_required(f):
    from models.data_models import AdminUser
    @wraps(f)
    def decorator(*args, **kwargs):
        auth_token = None
        current_user = None

        if 'Authorization' in request.headers:
            try:
                auth_token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                auth_token = None

        if not auth_token:
            return jsonify({'error': True, 'errorMessage': 'A valid token is missing.'}), 401

        try:
            admin_user_id = AdminUser.decode_auth_token(auth_token, throw_exception=True)
            current_user = AdminUser.query.filter_by(id=admin_user_id).first()
        except:
            return jsonify({'error': True, 'errorMessage': 'The provided token is invalid. Please log in again.'}), 401

        if not current_user:
            return jsonify({'error': True, 'errorMessage': 'The provided token is invalid. Please log in again.'}), 401

        _logger.info("Request made by: {} (#{})".format(current_user.email, current_user.id))
        return f(current_user, *args, **kwargs)

    return decorator
