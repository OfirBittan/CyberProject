import datetime

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import current_user, logout_user, login_required
from sqlalchemy import text

from .models import Customers
from . import db

views = Blueprint('views', __name__)


# Home page function: shows the Customers names for each User.
@views.route('/')
@login_required
def home():
    customers = Customers.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', data=customers, user=current_user)


# Logout function.
@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# Add customer page function:
# gets email (unique) and customer name.
@views.route('/customers', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')

        # # Safe version
        # customer = Customers.query.filter_by(email=email, user_id=current_user.id).first()

        # Unsafe version
        sql_query = text(f"SELECT * FROM customers WHERE email = '{email}' LIMIT 1")
        result = db.session.execute(sql_query)
        customer = result.fetchone()

        if customer:
            flash('Email already exists.', category='error')
        # # Without these checks the code will be more vulnerable
        # elif len(email) < 5:
        #     flash('Email must be greater than 4 characters.', category='error')
        # elif len(first_name) < 2:
        #     flash('First name must be greater than 1 character.', category='error')
        else:
            new_customer = Customers(email=email, first_name=first_name, user_id=current_user.id,
                                     date=datetime.datetime.now())
            db.session.add(new_customer)
            db.session.commit()
            flash(f'Added customer {new_customer.first_name}', category='success')
            return redirect(url_for('views.home'))
    return render_template("customers.html", user=current_user)
