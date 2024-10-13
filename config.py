import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'haroonkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_USERNAME = 'haroonwajid590@gmail.com'
    MAIL_PASSWORD = 'sqvz ttsc lpdn abay'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
