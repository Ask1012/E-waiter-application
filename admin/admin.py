from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
from models import db, Owner, Owner_profile, Waiter, User, Items, TableSession, Bill, Subscription, Contact

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

ADMIN_USERNAME = "ask"
ADMIN_PASSWORD = "ask1012"

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    owners = Owner.query.all()
    profiles = Owner_profile.query.all()
    waiters = Waiter.query.all()
    users = User.query.all()
    items = Items.query.all()
    tables = TableSession.query.all()
    bills = Bill.query.all()
    subscriptions = Subscription.query.all()
    contacts = Contact.query.all()
    
    return render_template('admin_dashboard.html', owners=owners, profiles=profiles, waiters=waiters,
                           users=users, items=items, tables=tables, bills=bills, subscriptions=subscriptions,
                           contacts=contacts)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.secret_key = Config.SECRET_KEY
    app.run(debug=True)
