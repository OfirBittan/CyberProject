# Imports.
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()


def create_app():
    # Init app with Flask library.
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    db_name = "mydatabase"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://rejim:rejim123@localhost/{db_name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Init Flask-Mail to send random value for forgot password
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'verizzonmand2@gmail.com'
    app.config['MAIL_PASSWORD'] = 'hidb cigz wsco wlth'
    app.config['MAIL_DEFAULT_SENDER'] = 'verizzonmand2@gmail.com'

    # Init Flask-Mail with the Flask app.
    mail = Mail()
    mail.init_app(app)

    # Init SQLAlchemy with the Flask app.
    db.init_app(app)

    # Imports.
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Customers

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id_val):
        return User.query.get(int(id_val))

    return app
