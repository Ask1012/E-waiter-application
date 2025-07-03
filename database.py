from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from itsdangerous import URLSafeSerializer
from flask import Flask
from config import Config


db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    serializer = URLSafeSerializer(app.config['SECRET_KEY'])

    with app.app_context():
        db.create_all()  # Ensure tables are created

        # Import and register routes AFTER app is created
        from routes import register_routes  
        register_routes(app)

    return app
