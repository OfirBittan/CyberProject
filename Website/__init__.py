from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

mail = Mail()
db = SQLAlchemy()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://rejim:rejim123@localhost/mydatabase'

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Configure Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'verizzonmand2@gmail.com'
    app.config['MAIL_PASSWORD'] = 'hidb cigz wsco wlth'
    app.config['MAIL_DEFAULT_SENDER'] = 'verizzonmand2@gmail.com'

    # Initialize Flask-Mail with the Flask app
    mail.init_app(app)

    # Initialize SQLAlchemy with the Flask app
    db.init_app(app)

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
    def load_user(id):
        return User.query.get(int(id))

    return app
