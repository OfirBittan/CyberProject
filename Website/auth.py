import os
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from flask_login import login_user, current_user
from passlib.hash import pbkdf2_sha256

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


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = request.form.get('email')
    current_password = request.form.get('currentPassword')
    new_password = request.form.get('newPassword')
    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        if user:
            if verify_password(current_password, user.password):
                if len(new_password) < 7:
                    flash('Password must be at least 7 characters.', category='error')
                else:
                    hashed_new_password = generate_password_hash(new_password)
                    user.password = hashed_new_password
                    db.session.commit()
                    flash('Changed password!', category='success')
                return redirect(url_for('auth.login'))
            else:
                flash('Incorrect current password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("reset_password.html", user=current_user)


# Helper functions for password handling
def generate_password_hash(password):
    salt = os.urandom(16)
    return pbkdf2_sha256.using(salt=salt, rounds=1000).hash(password)


def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)
