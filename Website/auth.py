# Imports.
import os
import random
from datetime import datetime, timedelta

from sqlalchemy import text

from .models import User, PasswordHistory
from passlib.hash import pbkdf2_sha256
import hashlib
from . import db
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, current_user
from flask_mail import Message, Mail
from Website import passwordCheck

MAX_LOGIN_ATTEMPTS = 3  # Max num of login attempts before blocking user.
BLOCK_DURATION = 1  # Minutes of user being blocked.
SECRET_KEY = os.urandom(16)  # Secret key for HMAC.

mail = Mail()
auth = Blueprint('auth', __name__)


# Login function:
# verifies the user's details,
# blocks user if enter 3 incorrect passwords.
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # # Safe version
        # user = User.query.filter_by(email=email).first()

        # Unsafe version
        sql_query = text(f"SELECT * FROM user WHERE email = '{email}' LIMIT 1;")
        result = db.session.execute(sql_query)
        user = result.fetchone()

        if user:  # Checks if the user exists according to email.
            if user.is_blocked:  # Checks if the user blocked after 3 attempts.
                if user.block_expiration > datetime.utcnow():
                    flash('Account is temporarily blocked. Please try again later.', category='error')
                    return redirect(url_for('auth.login'))
                else:
                    user.login_attempts = 0
                    user.is_blocked = False
                    user.block_expiration = None
            if verify_password(password, user.password):  # Checks if the password is correct.
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                handle_failed_login(user)
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)


# If the user enters correct mail but incorrect password:
# add up the number of times it happens.
# if the number of times it happened is 3 block the user for 1 minute.
def handle_failed_login(user):
    user.login_attempts += 1
    user.last_failed_attempt = datetime.utcnow()
    if user.login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.is_blocked = True
        user.block_expiration = datetime.utcnow() + timedelta(minutes=BLOCK_DURATION)
    db.session.commit()


# Sign up function:
# checking email, first name, password.
# if it passes the checks we add a new user to db.
@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # # Safe version
        # user = User.query.filter_by(email=email).first()

        # Unsafe version
        sql_query = text(f"SELECT * FROM user WHERE email = '{email}' LIMIT 1")
        result = db.session.execute(sql_query)
        user = result.fetchone()

        if user:  # Check if email already exists in db.
            flash('Email already exists.', category='error')
        # # Without these checks the code will be more vulnerable
        # elif len(email) < 5:  # Check email length.
        #     flash('Email address must be greater than 4 characters.', category='error')
        # elif len(first_name) < 2:  # Check first name length.
        #     flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:  # Check same 2 passwords.
            flash('Passwords do not match.', category='error')
        else:
            if passwordCheck.main_check(None, password1):  # Check if the password is according to requirements.
                hashed_password = generate_password_hash(password1)
                new_user = User(email=email, first_name=first_name, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                PasswordHistory.save_password_history(new_user.id, hashed_password)
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)


# Password hash generating.
def generate_password_hash(password):
    salt = os.urandom(16)
    return pbkdf2_sha256.using(salt=salt, rounds=1000).hash(password)


# Password verifying with hash in log in.
def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)


# Forgot password function:
# generate random,
# send it via email,
# store the code in the session or database for verification later.
@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    user = None
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            code = generate_random_code()
            send_reset_code_email(email, code)
            session['reset_code_hash'] = hashlib.sha1(code.encode()).hexdigest()
            flash('A code has been sent to your email. Please check your inbox.', category='success')
            return redirect(url_for('auth.verify_code_from_mail', email=email))
        else:
            flash('Email does not exist.', category='error')
    return render_template("forgot_password.html", user=user)


# Generate a random code using SHA-1 for email.
def generate_random_code():
    random_code = str(random.randint(10000, 99999))
    hashed_code = hashlib.sha1(random_code.encode()).hexdigest()
    return hashed_code


# Send code to email.
def send_reset_code_email(email, code):
    msg = Message('Reset Your Password', recipients=[email])
    msg.body = f'Your reset password code is: {code}'
    mail.send(msg)


# Verify code from mail function.
@auth.route('/verify_code_from_mail', methods=['GET', 'POST'])
def verify_code_from_mail():
    email = request.args.get('email')
    user = current_user
    if request.method == 'POST':
        code = request.form.get('code')
        if VerificationCode.verify_code(email, code):
            return redirect(url_for('auth.reset_password', email=email, code=code))
        else:
            flash('Invalid code. Please try again.', category='error')
    return render_template("code_input.html", user=user)


# Reset password function:
# after entering correct code from email go to the reset password screen.
# entering new password that will be saved in the db after hashing.
@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')  # The random value from the mail entered by the user.
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        user = User.query.filter_by(email=email).first()
        if user:
            # Check if the random value entered by the user matches the stored hash of the email code send.
            if VerificationCode.verify_code(email, code):
                if new_password != confirm_password:
                    flash('Passwords do not match.', category='error')
                else:
                    if passwordCheck.main_check(user, new_password):
                        hashed_new_password = generate_password_hash(new_password)
                        user.password = hashed_new_password
                        db.session.commit()
                        PasswordHistory.save_password_history(user.id, hashed_new_password)
                        flash('Password changed successfully!', category='success')
                        return redirect(url_for('auth.login'))
            else:
                flash('Invalid or expired reset token.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("reset_password.html", user=current_user, code=request.args.get('code'),
                           email=request.args.get('email'))


# Mail code verification class.
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # SHA1 hashes are 40 characters long.
    code_hash = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    # Define a relationship with the User model.
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
