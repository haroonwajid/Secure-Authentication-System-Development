import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'haroonkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_USERNAME = 'replace with email'
    MAIL_PASSWORD = 'replace with app password'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
