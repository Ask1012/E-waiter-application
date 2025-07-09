import os
from datetime import timedelta

class Config:
    SECRET_KEY =  os.getenv("SECRET_KEY", "dev-secret") 
    SQLALCHEMY_DATABASE_URI =  os.getenv('DB_CONNECTION_STR')
    

    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
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

    # File Uploads
    UPLOAD_FOLDER = 'static/uploads/'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
