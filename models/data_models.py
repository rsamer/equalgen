from flask_sqlalchemy import SQLAlchemy
from flask_admin.contrib.sqla import ModelView
from authentication import BcryptBasicAuth
from error_handling.auth_exception import AuthException
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask import redirect
import enum
import hashlib
import jwt


db = SQLAlchemy()
bcrypt = Bcrypt()
basic_auth = BcryptBasicAuth(bcrypt=bcrypt)
SECRET_KEY = '&39HwX)a!ru{XKKYr(4D'  # app.config.get('SECRET_KEY') TODO: outsource!!
BCRYPT_LOG_ROUNDS = 4  # app.config.get('BCRYPT_LOG_ROUNDS') TODO: outsource!!


class GenderType(enum.Enum):
    MALE = 1
    FEMALE = 2
    DIVERSE = 3


class DeleteReasonType(enum.Enum):
    OTHER = 0
    DUPLICATE = 1
    NO_INTEREST = 2
    TOO_EXPENSIVE = 3
    PRIVACY_CONCERNS = 4


class AdminUser(db.Model):
    __tablename__ = "admin_user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = bcrypt.generate_password_hash(password, BCRYPT_LOG_ROUNDS).decode()
        self.registered_on = datetime.now()

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(hours=12, minutes=0, seconds=0),
                'iat': datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token, throw_exception=True):
        """
        Validates the authentication token
        :param throw_exception:
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError as e:
            if not throw_exception:
                return 'Signature expired. Please log in again.'
            else:
                raise e
        except jwt.InvalidTokenError as e:
            if not throw_exception:
                return 'Invalid token. Please log in again.'
            else:
                raise e


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_token'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        return False


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.Enum(GenderType), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, unique=False, default=True)
    is_banned = db.Column(db.Boolean, unique=False, default=False)
    is_deleted = db.Column(db.Boolean, unique=False, default=False)
    profile_image_path = db.Column(db.String(255), nullable=True)
    creation_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login_time = db.Column(db.DateTime, default=None, nullable=True)
    deletion_time = db.Column(db.DateTime, default=None, nullable=True)
    deletion_reason = db.Column(db.Enum(DeleteReasonType), nullable=False)

    def __init__(self, username: str, firstname: str, lastname: str, gender: GenderType, email: str, password: str):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.gender = gender
        self.email = email
        self.password = password
        self.is_active = False
        self.last_login_time = None
        self.deletion_time = None

    def perform_login(self):
        # TODO: add entry to activity log...
        self.last_login_time = datetime.utcnow()

    def ban_account(self):
        # TODO: add ban entry to activity log...
        self.is_banned = True

    def delete_account(self, reason: DeleteReasonType):
        # TODO: add deleted entry to activity log...
        self.is_deleted = True
        self.deletion_time = datetime.utcnow()
        self.deletion_reason = reason

    def __repr__(self):
        return '<User #%d> "%s %s"' % (self.id, self.firstname, self.lastname)


class Questionnaire(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    questions = db.relationship('Question', lazy='select', backref=db.backref('question', lazy='select'),
                                cascade="all, delete-orphan")
    creation_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return '<Questionnaire #%d: "%s">' % (self.id, self.title)

    def __hash__(self):
        sha = hashlib.sha256()
        unique_tuple = (self.id, self.title)
        sha.update(str(unique_tuple).encode())
        return sha.hexdigest()


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(255), nullable=False)
    image_path = db.Column(db.String(255), nullable=True)
    questionnaire_id = db.Column(db.Integer, db.ForeignKey('questionnaire.id'), nullable=False)
    creation_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return '<Question #%d> "%s"' % (self.id, self.text)


class StandardModelView(ModelView):
    page_size = 50
    column_hide_backrefs = True
    create_modal = False
    edit_modal = True
    can_export = True

    def __init__(self, model, session, name=None, category=None, endpoint=None, url=None, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        super(StandardModelView, self).__init__(model, session, name=name, category=category, endpoint=endpoint, url=url)

    def is_accessible(self):
        if not basic_auth.authenticate():
            raise AuthException('Not authenticated. Refresh the page.')
        else:
            return True

    def inaccessible_callback(self, name, **kwargs):
        return redirect(basic_auth.challenge())
