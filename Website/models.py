from datetime import datetime

from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


# User db model.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    login_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime)
    is_blocked = db.Column(db.Boolean, default=False)  # Flag to indicate if the user is blocked.
    block_expiration = db.Column(db.DateTime)  # Timestamp indicating when the block expires.
    customers = db.relationship('Customers')  # Connect to the user's customer table.
    password_histories = db.relationship('PasswordHistory', backref='user',
                                         lazy=True)  # Connect to the user's password history table.

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


# PasswordHistory db table saves for every user the last 3 passwords history.
class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Get the last 3 password history records for the user.
    # Delete the oldest password history record if there are already 3.
    # Add the new password history record.
    @staticmethod
    def save_password_history(user_id, password_hash):
        last_three_histories = PasswordHistory.query.filter_by(user_id=user_id).order_by(
            PasswordHistory.timestamp.desc()).limit(3).all()
        if len(last_three_histories) == 3:
            db.session.delete(last_three_histories[-1])
            db.session.commit()
        new_password_history = PasswordHistory(user_id=user_id, password_hash=password_hash)
        db.session.add(new_password_history)
        db.session.commit()
