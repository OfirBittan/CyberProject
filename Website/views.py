from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import current_user, logout_user, login_required
from .models import Customers
from . import db

views = Blueprint('views', __name__)


@views.route('/')
@login_required
def home():
    customers = Customers.query.all()
    return render_template('home.html', data=customers, user=current_user)


@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@views.route('/customers', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        customer = Customers.query.filter_by(email=email).first()
        if customer:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        else:
            new_customer = Customers(email=email, first_name=first_name)
            db.session.add(new_customer)
            db.session.commit()
            flash(f'Added customer {new_customer.first_name}', category='success')
            return redirect(url_for('views.home'))
    return render_template("customers.html", user=current_user)
