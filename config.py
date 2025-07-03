import os
from datetime import timedelta

class Config:
    SECRET_KEY =  os.getenv("SECRET_KEY", "dev-secret") 
    SQLALCHEMY_DATABASE_URI =  os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://root:password@localhost:3306/hotel')
    SQLALCHEMY_DATABASE_URI = (
    f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
    f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    f"?ssl_ca=certs/isrgrootx1.pem"
)

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
