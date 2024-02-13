import os
import random
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from flask_login import login_user
from passlib.hash import pbkdf2_sha256
import hashlib
from flask_mail import Message
from flask_mail import Mail
from flask_login import current_user
from flask import session

mail = Mail()

auth = Blueprint('auth', __name__)

# Define a secret key for HMAC
SECRET_KEY = os.urandom(16)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if verify_password(password, user.password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            hashed_password = generate_password_hash(password1)
            new_user = User(email=email, first_name=first_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)


# Helper functions for password handling
def generate_password_hash(password):
    salt = os.urandom(16)
    return pbkdf2_sha256.using(salt=salt, rounds=1000).hash(password)


def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)


@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    user = None
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # generate random code
            code = generate_random_code()
            # Generate and send code via email
            send_reset_code_email(email, code)
            # Store the code in the session or database for verification later
            session['reset_code_hash'] = hashlib.sha1(code.encode()).hexdigest()
            # session['reset_code'] = code
            flash('A code has been sent to your email. Please check your inbox.', category='success')
            # Redirect to code input page
            return redirect(url_for('auth.enter_code', email=email))
        else:
            flash('Email does not exist.', category='error')
    return render_template("forgot_password.html", user=user)


def generate_random_code():
    # Generate a random code
    random_code = str(random.randint(10000, 99999))
    # Hash the random code using SHA-1
    hashed_code = hashlib.sha1(random_code.encode()).hexdigest()
    return hashed_code


@auth.route('/enter_code', methods=['GET', 'POST'])
def enter_code():
    email = request.args.get('email')
    user = current_user
    if request.method == 'POST':
        code = request.form.get('code')
        # Verify the code
        if VerificationCode.verify_code(email, code):
            # Redirect to password reset page
            return redirect(url_for('auth.reset_password', email=email, code=code))
        else:
            flash('Invalid code. Please try again.', category='error')
    return render_template("code_input.html", user=user)


def send_reset_code_email(email, code):
    msg = Message('Reset Your Password', recipients=[email])
    msg.body = f'Your reset password code is: {code}'
    mail.send(msg)


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')  # The random value entered by the user
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        user = User.query.filter_by(email=email).first()
        if user:
            # Check if the code entered by the user matches the stored hash of the code
            if VerificationCode.verify_code(email, code):
                if new_password != confirm_password:
                    flash('Passwords do not match.', category='error')
                elif len(new_password) < 7:
                    flash('Password must be at least 7 characters.', category='error')
                else:
                    # Reset password
                    hashed_new_password = generate_password_hash(new_password)
                    user.password = hashed_new_password
                    db.session.commit()
                    flash('Password changed successfully!', category='success')
                    return redirect(url_for('auth.login'))
            else:
                flash('Invalid or expired reset token.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("reset_password.html", user=current_user, code=request.args.get('code'),
                           email=request.args.get('email'))


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_hash = db.Column(db.String(40), nullable=False)  # SHA1 hashes are 40 characters long
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    # Define a relationship with the User model
    user = db.relationship('User', backref=db.backref('verification_codes', lazy=True))

    @staticmethod
    def verify_code(email, code):
        # Retrieve the user based on the email
        stored_code_hash = session.get('reset_code_hash')
        if stored_code_hash:
            # Filter the VerificationCode model by user_id and code
            entered_code_hash = hashlib.sha1(code.encode()).hexdigest()
            if entered_code_hash == stored_code_hash:
                return True
        return False
