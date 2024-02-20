from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


# User db model.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    customers = db.relationship('Customers')  # Connect to the user's customer table.
    is_blocked = db.Column(db.Boolean, default=False)  # Flag to indicate if the user is blocked.
    block_expiration = db.Column(db.DateTime)  # Timestamp indicating when the block expires.
    login_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime)

    def __init__(self, email, password, first_name):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.login_attempts = 0
        self.last_failed_attempt = None
        self.is_blocked = False  # Initialize is_blocked as False.
        self.block_expiration = None  # Initialize block_expiration as None.


# Customers db table.
class Customers(db.Model):
    id_customer = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    first_name = db.Column(db.String(150))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
