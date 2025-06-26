import os
from datetime import timedelta

class Config:
    SECRET_KEY = 'ask'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/hotel'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_PERMANENT = False

    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'ak1074834@gmail.com'
    MAIL_PASSWORD = '/ask.in/kumbhar'

    # Stripe
    ***REMOVED***
    ***REMOVED***

    # File Uploads
    UPLOAD_FOLDER = 'static/uploads/'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
