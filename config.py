#!/usr/bin/env python3

import os
basedir = os.path.abspath(os.path.dirname(__file__))
sqlite_local_base = 'sqlite:///data/'
database_name = 'storage.sqlite'


class BaseConfig:
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'INSERT_YOUR_SECRET_KEY')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASK_ADMIN_SWATCH = 'cerulean'
    BASIC_AUTH_USERNAME = 'INSERT_USERNAME'
    BASIC_AUTH_PASSWORD = 'INSERT_YOUR_ENCRYPTED_KEY'
    GOOGLE_MAPS_KEY = 'INSERT_YOUR_KEY'
    API_ADMINS = [{
        "email": "first.last@email.com",
        "password": "INSERT_YOUR_PASSWORD"
    }]


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = sqlite_local_base + database_name


class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = sqlite_local_base + database_name + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = 'INSERT_YOUR_SECRET_KEY'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = sqlite_local_base + database_name
