from flask import Flask,render_template, request, jsonify, session,redirect,url_for,make_response,flash,send_file,json
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_login import UserMixin
import uuid
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeSerializer,BadSignature
from flask_bcrypt import Bcrypt
from datetime import timedelta,datetime,date,timezone
datetime.now(timezone.utc)
from werkzeug.utils import secure_filename
import qrcode,base64
from io import BytesIO
from decimal import Decimal
from flask_mail import Mail, Message
import os
import stripe


app = Flask(__name__)
app.secret_key = 'ask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/hotel'
app.config[' SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Use secure cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Make cookies inaccessible to JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF in cross-site requests
app.config['SESSION_PERMANENT'] = False  # Session expires when the browser is closed
app.config['MAIL_USERNAME'] = 'ak1074834@gmail.com'
app.config['MAIL_PASSWORD'] = '/ask.in/kumbhar'
YOUR_DOMAIN = "http://localhost:5000"
***REMOVED***

***REMOVED***

UPLOAD_FOLDER = 'static/uploads/'  # Folder to store uploaded photos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home' 

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
serializer = URLSafeSerializer(app.config['SECRET_KEY'])

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)


@app.after_request
def add_no_cache_headers(response):
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


@login_manager.user_loader
def load_user(user_id):
    owner = Owner.query.filter_by(owner_id=user_id).first()
    user = User.query.filter_by(user_id=user_id).first()
    waiter = Waiter.query.filter_by(waiter_id=user_id).first()
    if owner:
        return owner
    elif user:
        return user
    elif waiter:
        return waiter
    return None  # Explicitly return None if no user is found

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class Owner(db.Model, UserMixin):
    __tablename__ = 'hotel_owners'
    owner_id = db.Column(db.Integer, primary_key=True)
    owner_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    subscription_status = db.Column(
        db.Enum('trial', 'active', 'expired', name='subscription_status'),
        default='trial', nullable=False
    )
    
    # Define the relationship to User
    users = db.relationship('User', back_populates='owner', cascade="all, delete-orphan")
    items = db.relationship('Items', back_populates='owner', cascade="all, delete-orphan")
    waiters = db.relationship('Waiter', back_populates='owner', cascade="all, delete-orphan")
    bills = db.relationship('Bill', back_populates='owner', cascade="all, delete-orphan")
    owner_profiles = db.relationship('Owner_profile', back_populates='owner', cascade="all, delete-orphan")  # Fix here
    subscription = db.relationship('Subscription', back_populates='owner', uselist=False)
    table_sessions = db.relationship('TableSession', back_populates='owner', cascade="all, delete-orphan")

    @property
    def is_owner(self):
        return True  # Always true for Owner

    def get_id(self):
        return str(self.owner_id)
    
class Owner_profile(db.Model, UserMixin):
    __tablename__ = 'owner_profile'
    profile_id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    hotel_name = db.Column(db.String(100), nullable=True, unique=True)
    number_of_tables = db.Column(db.Integer, nullable=False, default=1)
    hotel_photo = db.Column(db.String(255), nullable=True)  # Stores the path to the photo
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    
    # Relationship to Owner
    owner = db.relationship('Owner', back_populates='owner_profiles')

    @property
    def hotel_details(self):
        return f"Hotel: {self.hotel_name}, Tables: {self.number_of_tables}"


 
class Waiter(db.Model,UserMixin):
    __tablename__ = 'waiters'
    waiter_id = db.Column(db.Integer, primary_key=True)
    waiter_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    joined_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    
    # Define the relationship to Owner
    owner = db.relationship('Owner', back_populates='waiters')
    bills = db.relationship('Bill', back_populates='waiter', cascade="all, delete-orphan")

    @property
    def is_active(self):
        return True 
    
    @property
    def is_waiter(self):
        return True
    
    def get_id(self):
        return str(self.waiter_id)
        
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id', ondelete='CASCADE'), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    
    # Define the relationship to Owner
    owner = db.relationship('Owner', back_populates='users')

    def __repr__(self):
        return f"<User(user_id={self.user_id}, username={self.username}, email={self.email})>"
    def get_id(self):
        return str(self.user_id)
    
class Items(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id', ondelete='CASCADE'), nullable=False)
    item_name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Integer,nullable=False)
    category = db.Column(db.String(50), nullable=False)
    
    # Define the relationship to Owner
    owner = db.relationship('Owner', back_populates='items')

    def __repr__(self):
        return f"<Items(item_id={self.item_id}, item_name={self.item_name}, price={self.price},category={self.category})>"


class TableSession(db.Model):
    __tablename__ = 'table_sessions'

    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer,db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    waiter_id = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum('free', 'occupied', name='status_enum'), default='occupied', nullable=False)
    data = db.Column(db.Text, nullable=True, default=json.dumps([]))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total= db.Column(db.Integer, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship('Owner', back_populates='table_sessions')

class Bill(db.Model):
    __tablename__ = 'bills'

    bill_id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    waiter_id = db.Column(db.Integer, db.ForeignKey('waiters.waiter_id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    bill_date = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)  # To store ordered items as JSON

    owner = db.relationship('Owner', back_populates='bills')
    waiter = db.relationship('Waiter', back_populates='bills')

class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    subscription_id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id', ondelete='CASCADE'), nullable=False)
    owner_name = db.Column(db.String(255), nullable=False)  
    owner_email = db.Column(db.String(255), nullable=False, unique=True)  
    status = db.Column(db.Enum('trial', 'active', 'expired', name='subscription_status'), default='trial', nullable=False)
    start_date = db.Column(db.DateTime, nullable=True)  
    end_date = db.Column(db.DateTime, nullable=True) 

    owner = db.relationship('Owner', back_populates='subscription')

    def is_expired(self):
        return self.end_date and datetime.utcnow() > self.end_date  

    
            
# Auto-update the subscription status before any request
@app.before_request
def check_subscriptions():
    expired_subs = Subscription.query.filter(Subscription.end_date < datetime.utcnow(), Subscription.status != "expired").all()
    for sub in expired_subs:
        sub.status = "expired"
        sub.owner.subscription_status = "expired"
    db.session.commit()

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(255), unique=True, nullable=False)
    event_type = db.Column(db.String(255), nullable=False)
    event_data = db.Column(db.JSON, nullable=False)


@app.route('/')
def home():
    if current_user.is_authenticated and isinstance(current_user, Owner):
        # Check subscription status
        if current_user.subscription_status == 'expired':
            flash("Your subscription has expired. Please renew.", "warning")
            return redirect(url_for('payment_page'))  # Redirect to payment

        owner_id = current_user.owner_id
        today_start = datetime.combine(date.today(), datetime.min.time())
        today_end = datetime.combine(date.today(), datetime.max.time())

        # Fetch today's bills
        bills = Bill.query.filter(
            Bill.owner_id == owner_id,
            Bill.bill_date >= today_start,
            Bill.bill_date <= today_end
        ).order_by(Bill.bill_date.desc()).all()

        # Calculate income
        today_income = sum(bill.total_amount for bill in bills)

        # Convert details to JSON if stored as a string
        for bill in bills:
            if isinstance(bill.details, str):
                bill.details = json.loads(bill.details)

        return render_template(
            'index.html',
            owner=current_user.owner_name,
            owner_id=owner_id,
            bills=bills,
            total_amount=today_income,
            todays_bills=len(bills)
        )

    return render_template('index.html')


@app.route('/waiter_register', methods=['GET'])
def waiter_register():
    # Render the waiter registration page
    return render_template('waiter_register.html')



# Registration route
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        owner_id = request.args.get('owner_id', None)
        # Render the registration page for GET request
        return render_template('register.html', owner_id=owner_id)
    
    if request.method == 'POST':
        user_type = request.form.get('user_type')  # 'owner', 'user', or 'waiter'
        username = request.form.get('username')
        email = request.form.get('email', None)  # Email might not be required for waiter
        password = request.form.get('password')

        if user_type == 'owner':
    # Check if owner already exists
                    existing_owner_email = Owner.query.filter_by(email=email).first()
                    existing_owner_name = Owner.query.filter_by(owner_name=username).first()
                    if existing_owner_email:
                        flash("Email already registered for owner", "error")
                        return redirect(url_for('register'))
                    if existing_owner_name:
                        flash("Username already registered for owner", "error")
                        return redirect(url_for('register'))

                    # Hash the password
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                    # Create a new owner
                    new_owner = Owner(owner_name=username, email=email, password=hashed_password)
                    db.session.add(new_owner)
                    db.session.flush() 
                   

                    trial_days = 1  # Set trial period duration
                    subscription = Subscription(
                    owner_id=new_owner.owner_id,
                    owner_name=new_owner.owner_name,
                    owner_email=new_owner.email,
                    status='trial',
                    start_date=datetime.utcnow(),
                    end_date=datetime.utcnow() + timedelta(days=trial_days)
                   )


                    db.session.add(subscription)

                    # Commit all changes
                    db.session.commit()

                    flash("Registration successful! Your free trial has started.", "success")
                    return redirect(url_for('owner_login'))


        elif user_type == 'user':
            # User registration: owner_id is required
            owner_id = request.form.get('owner_id')  # Required field
            if not owner_id:
                return jsonify({'message': 'Owner ID is required for user registration.'}), 400

            # Validate owner existence
            decrypted_owner_id = serializer.loads(owner_id)
            owner = Owner.query.get(decrypted_owner_id)
            if not owner:
                flash("Invalid owner ", "error")
                return redirect(url_for('register'))

            # Check if user already exists
            existing_user_email = User.query.filter_by(email=email).first()
            existing_user_name = User.query.filter_by(username=username).first()
            if existing_user_email:
                return jsonify({'message': 'Email already registered for a user.'}), 409
            if existing_user_name:
                flash("User name already registered", "error")
                return redirect(url_for('register'))

            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create a new user
            new_user = User(owner_id=decrypted_owner_id, username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('user_login'))

        elif user_type == 'waiter':
            # Get form inputs
                owner_id = request.form.get('owner_id')
                username = request.form.get('username')  # Ensure username is retrieved
                password = request.form.get('password')  # Ensure password is retrieved

    # Validate inputs
                if not owner_id or not username or not password:
                        flash("Owner ID, username, and password are required", "error")
                        return redirect(url_for('waiter_register'))

    # Check if owner exists
                owner = Owner.query.get(owner_id)
                if not owner:
                    flash("Invalid owner ID", "error")
                    return redirect(url_for('waiter_register'))

    
                existing_waiter_name = Waiter.query.filter_by(waiter_name=username).first()
                if existing_waiter_name:
                    flash("Username already registered for a waiter, Try another", "error")
                    return redirect(url_for('waiter_register'))

   
                try:
                      hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                except Exception as e:
                    flash(f"Error hashing password: {e}", "error")
                    return redirect(url_for('waiter_register'))

   
                try:
                    new_waiter = Waiter(owner_id=owner_id, waiter_name=username, password=hashed_password)
                    db.session.add(new_waiter)
                    db.session.commit()
                    flash("Waiter registered successfully!", "success")
                    return redirect(url_for('waiter_login'))
                except Exception as e:
                        db.session.rollback()  # Rollback in case of an error
                        flash(f"Error registering waiter: {e}", "error")
                        return redirect(url_for('waiter_register'))

        else:
            return jsonify({'message': 'Invalid user type.'}), 400

@app.route('/owner_login', methods=['POST', 'GET'])
def owner_login():
    if request.method == 'GET':
        return render_template('owner_login.html', user_type='Owner')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        owner = Owner.query.filter_by(email=email).first()
        if owner:
            print("Entered Password:", password)
            print("Stored Hash:", owner.password)
            print("Match Result:", bcrypt.check_password_hash(owner.password, password))

            if bcrypt.check_password_hash(owner.password, password):
                owner_id = serializer.dumps(owner.owner_id)
                login_user(owner)
                return redirect(url_for('home', owner_id=owner_id))
            else:
                flash("Invalid password for Owner", "error")
                return redirect(url_for('owner_login'))
        print("Entered Password:", password)
        print("Stored Hash:", owner.password)
        print("Match Result:", bcrypt.check_password_hash(owner.password, password))

        flash("Invalid email or password for Owner", "error")
        return redirect(url_for('owner_login'))
    

# User Login Route
@app.route('/user_login', methods=['POST', 'GET'])
def user_login():
    if request.method == 'GET':
        return render_template('user_login.html', user_type='User')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('hotel'))
            else:
                flash("Invalid password for User", "error")
                return redirect(url_for('user_login'))
        
        flash("Invalid email or password for User", "error")
        return redirect(url_for('user_login'))

@app.route('/waiter_login', methods=['POST', 'GET'])
def waiter_login():
    if request.method == 'GET':
        return render_template('waiter_login.html', user_type='Waiter')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Ensure inputs are not empty
        if not email or not password:
            flash("Email and password are required", "error")
            return redirect(url_for('waiter_login'))

        # Check for Waiter login
        waiter = Waiter.query.filter_by(waiter_name=email).first()
        if waiter:
            # Ensure password is not None
            if waiter.password is None:
                flash("Error: Waiter's password is not set", "error")
                return redirect(url_for('waiter_login'))

            if bcrypt.check_password_hash(waiter.password, password):
                login_user(waiter)
                return redirect(url_for('waiter_dashboard'))  
            else:
                flash("Invalid password for Waiter", "error")
                return redirect(url_for('waiter_login'))

        flash("Invalid email or password for Waiter", "error")
        return redirect(url_for('waiter_login'))

    
# Route to log out owner 
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    
    logout_user()
    return redirect(url_for('home'))

@app.route('/contact')
def contact():
    return render_template('contact_us.html')

@app.route('/about')
def about():
    return render_template('about_us.html')

@app.route('/waiter_dashboard', methods=['GET', 'POST'])
@login_required
def waiter_dashboard():
    items_by_category = {}
    owner_name = "Unknown Owner"
    items = []  
    if isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        # Redirect to an error page or deny access
        return render_template('error.html', title="Access Denied", message="Only waiters can perform this action."), 403
    
    if isinstance(current_user, Waiter) :
        # Fetch items for the waiter if authenticated
        owner = db.session.get(Owner, current_user.owner_id)

        if owner:
            items = Items.query.filter_by(owner_id=current_user.owner_id).all()
            owner_name = owner.owner_name
    

  # No owner ID provided, no items to display

    # Group items by category
    for item in items:
        if item.category not in items_by_category:
            items_by_category[item.category] = []
        items_by_category[item.category].append({
            "item_name": item.item_name,
            "price": item.price,
            "id": item.item_id  # Include other fields if needed
        })

    waiter_id=current_user.waiter_id
    owner_id=current_user.owner_id
    try : 
        owner_profile = Owner_profile.query.filter_by(owner_id=current_user.owner_id).first() 
        table_count = owner_profile.number_of_tables
    except Exception as e :
        table_count=0
    # Render the waiter dashboard template
    return render_template('waiter_dashboard.html', owner_id=owner_id,waiter_id=waiter_id,items_by_category=items_by_category,table_count=table_count)

@app.route('/hotel', methods=['GET', 'POST'])
def hotel():  
    items_by_category = {}
    owner_name = "Unknown Owner"

    if current_user.is_authenticated and isinstance(current_user, (User, Owner,Waiter)):
        # Fetch the owner and items for authenticated users
        
        owner = db.session.get(Owner, current_user.owner_id)
        items = Items.query.filter_by(owner_id=current_user.owner_id).all()
        owner_name = owner.owner_name if owner else "Unknown Owner"
    else:
        # Fetch the owner and items for non-authenticated users
        owner_id = request.args.get('owner_id')
        if owner_id:
            owner_id = serializer.loads(owner_id)  # Decode the owner ID
            owner = db.session.get(Owner, owner_id)
            items = Items.query.filter_by(owner_id=owner_id).all()
            owner_name = owner.owner_name if owner else "Unknown Owner"
        else:
            items = []  # No owner ID provided, so no items to display

    # Group items by category
    for item in items:
        if item.category not in items_by_category:
            items_by_category[item.category] = []  # Initialize a new list for the category
        items_by_category[item.category].append(item)  # Append item to the correct category

    # Render the template
    return render_template('hotel.html', owner=owner_name, items_by_category=items_by_category)

@app.route('/add_hotel_profile', methods=['GET', 'POST'])
@login_required
def add_hotel_profile():
    profile = Owner_profile.query.filter_by(owner_id=current_user.owner_id).first()

    if request.method == 'POST':
        # Get form data
        hotel_name = request.form.get('hotel_name')
        number_of_tables = request.form.get('number_of_tables')
        file = request.files.get('hotel_photo')

        # Validate form fields
        if not hotel_name or not number_of_tables:
            flash("All fields are required except the photo!", "danger")
            return redirect(url_for('add_hotel_profile'))

        try:
            # If profile does not exist, create a new one
            if profile is None:
                profile = Owner_profile(owner_id=current_user.owner_id)

            # Handle photo upload
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                profile.hotel_photo = filepath  # Save the new photo path

            # Update or set profile details
            profile.hotel_name = hotel_name
            profile.number_of_tables = int(number_of_tables)

            # Add to session if new, commit changes
            if profile.profile_id is None:
                db.session.add(profile)

            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('add_hotel_profile'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}", "danger")

    # Render the profile page with profile details
    return render_template('add_hotel_profile.html', profile=profile,owner_id=current_user.owner_id)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        # Redirect to an error page or deny access
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403
    
    items_by_category = {}
    items = Items.query.filter_by(owner_id=current_user.owner_id).all()
    for item in items:
        if item.category not in items_by_category:
            items_by_category[item.category] = []
        items_by_category[item.category].append(item)

    if request.method == 'GET':
        return render_template('add_product.html', items=items, items_by_category=items_by_category)

    if request.method == 'POST':
        # Handle form submission
        item_name = request.form.get('itemName')
        item_price = request.form.get('itemPrice')
        selected_category = request.form.get('itemCategory')
        custom_category = request.form.get('customCategory')

        # Determine which category to use
        item_category = custom_category if custom_category.strip() else selected_category

        if not item_category:
            flash("Please select or enter a category.", "error")
            return render_template('add_product.html', items=items, items_by_category=items_by_category)

        # Create and save the new item
        new_item = Items(
            owner_id=current_user.owner_id,
            item_name=item_name,
            price=item_price,
            category=item_category
        )
        db.session.add(new_item)
        db.session.commit()

        flash("Item added successfully", "success")
        return redirect(url_for('add_item'))  # Redirect to refresh the page and show the updated list

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        # Redirect to an error page or deny access
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403

    # Fetch the item to be edited
    
    item = Items.query.get_or_404(item_id)
    if item.owner_id != current_user.owner_id:
        # Ensure the item belongs to the current user (Owner)
        return render_template('error.html', title="Unauthorized", message="You do not have permission to edit this item."), 403

    if request.method == 'GET':
        items_by_category = {}
        items = Items.query.filter_by(owner_id=current_user.owner_id).all()
        for item in items:
             if item.category not in items_by_category:
                  items_by_category[item.category] = []
                  items_by_category[item.category].append(item)
        item = Items.query.get_or_404(item_id)
       # Render the edit page with current item details
        return render_template('edit_product.html', item=item,items_by_category=items_by_category)
    if request.method == 'POST':
        # Handle form submission to update item details
        item.item_name = request.form.get('itemName')
        item.price = request.form.get('itemPrice')
        item.category = request.form.get('itemCategory')

        # Save the updated item to the database
        db.session.commit()

        flash("Item updated successfully", "success")
        return redirect(url_for('add_item'))  # Redirect to the add_item page to refresh the list

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        # Redirect to an error page or deny access
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403

    # Fetch the item to be deleted
    item = Items.query.get_or_404(item_id)
    
    if item.owner_id != current_user.owner_id:
        # Ensure the item belongs to the current user (Owner)
        return render_template('error.html', title="Unauthorized", message="You do not have permission to delete this item."), 403

    # Delete the item from the database
    db.session.delete(item)
    db.session.commit()

    flash("Item deleted successfully", "success")
    return redirect(url_for('add_item'))  # Redirect to the add_item page to refresh the list

@app.route('/add_offer', methods=['GET', 'POST'])
@login_required
def add_offer():
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        flash("Only owners can perform this action.", "danger")
        return render_template('error.html')

    items = Items.query.filter_by(owner_id=current_user.owner_id).all()

    if request.method == 'POST':
        item_id = request.form.get('item')
        discount = request.form.get('discount')

        if not item_id or not discount:
            flash("Please select an item and enter a valid discount.", "danger")
            return redirect(url_for('add_offer'))

        item = Items.query.get(item_id)
        if item:
            # Apply discount logic
            
            discount_percentage = Decimal(discount) / 100
            item.price = item.price * (1 - discount_percentage)
            db.session.commit()
            flash(f"Discount of {discount}% applied to {item.item_name}!", "success")
            return redirect(url_for('add_offer'))

        flash("Item not found.", "danger")

    return render_template('add_offer.html', items=items)


@app.route('/search_items', methods=['GET'])
@login_required
def search_items():
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        return jsonify({"error": "Unauthorized access"}), 403

    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({"items": []})  # Return empty list if no query provided

    # Filter items based on the query and current owner's items
    items = Items.query.filter(
        Items.item_name.ilike(f"%{query}%"),
        Items.owner_id == current_user.owner_id
    ).all()

    # Convert items to a JSON-serializable format
    items_data = [{"item_id": item.item_id, "item_name": item.item_name} for item in items]

    return jsonify({"items": items_data})

# Route to render kitchen page
@app.route('/kitchen')
@login_required
def kitchen():
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403
    return render_template('kitchen.html',  owner_id=current_user.owner_id)



   

@app.route('/generate_qr')
@login_required
def generate_qr(): 
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter) :
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403# Generate QR Code data URL dynamically for the owner_id
    owner_id= current_user.owner_id
    qr_data = url_for('hotel', owner_id=owner_id, _external=True)

    # Generate QR Code image
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert QR code image to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    owner_id = serializer.dumps(owner_id)
    return render_template('qr_display.html', qr_base64=qr_base64, owner_id=owner_id)

@app.route('/select_table', methods=['POST'])
@login_required
def select_table():
    data = request.json
    table_id = data['table_id']
    waiter_id = data['waiter_id']
    owner_id = data['owner_id']

    session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()

    if session:
        if session.waiter_id == waiter_id:
            message = "You are already serving this table."
        else:
            message = "This table is occupied by another waiter."
        return jsonify({'message': message, 'data': json.loads(session.data)}), 200

    # Create a new session for the table
    new_session = TableSession(
        table_id=table_id,
        owner_id=owner_id,
        waiter_id=waiter_id,
        status='occupied',
        data=json.dumps([])
    )
    db.session.add(new_session)
    db.session.commit()

    return jsonify({'message': f"Table {table_id} assigned to you.", 'data': []}), 201

    
@app.route('/add_menu_item', methods=['POST'])
@login_required
def add_menu_item():
    data = request.json
    table_id = data['table_id']
    waiter_id = data['waiter_id']
    owner_id = data['owner_id']
    item_name = data['item_name']
    price = data['price']
    quantity = data['quantity']

    # Find the table session for the given table and owner
    session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()

    if not session:
        return jsonify({'message': 'Table not found or unauthorized access.'}), 403

    # Add item to session data (the bill)
    session_data = json.loads(session.data)
    # Check if the item already exists in the session data, then update quantity
    item_found = False
    for item in session_data:
        if item['item_name'] == item_name:
            item['quantity'] += quantity  # Increase quantity if the item already exists
            item_found = True
            session.total = (session.total or 0) + price
            break
    
    if not item_found:
        # If the item doesn't exist, add it to the session data
        session.total = (session.total or 0) + price
        session_data.append({'item_name': item_name, 'price': price, 'quantity': quantity})

    session.data = json.dumps(session_data)
    db.session.commit()

    return jsonify({'message': 'Item added/updated successfully.', 'data': session_data}), 200

@app.route('/remove_menu_item', methods=['POST'])
@login_required
def remove_menu_item():
    data = request.json
    table_id = data['table_id']
    waiter_id = data['waiter_id']
    owner_id = data['owner_id']
    item_name = data['item_name']

    # Find the table session for the given table and owner
    session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()

    if not session:
        return jsonify({'message': 'Table not found or unauthorized access.'}), 403

    # Remove item from session data (the bill)
    session_data = json.loads(session.data)
    for item in session_data :
        if item['item_name'] == item_name :
            price=item['price']
            q=item['quantity']
    session_data = [item for item in session_data if item['item_name'] != item_name]
    session.total = session.total - price*q
    total= session.total
    print(price)
    session.data = json.dumps(session_data)
    db.session.commit()

    return jsonify({'message': 'Item removed successfully.', 'data': session_data,'total':total}), 200



@app.route('/view_bill', methods=['GET'])
def view_bill():
    table_id = request.args.get('table_id')
    owner_id = request.args.get('owner_id')

    session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()

    if not session:
        return jsonify({'message': 'Table not found.'}), 404
    total=session.total
    return jsonify({'data': json.loads(session.data),'total' :total}), 200

@app.route('/complete_bill', methods=['POST'])
@login_required
def complete_bill():
    data = request.json
    table_id = data['table_id']
    owner_id = data['owner_id']
    total_amount = data.get('total_amount', 0.0)  # Assuming the total amount is sent in the request

    session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()

    if not session:
            return jsonify({'message': 'Table not found.'}), 404

        # Calculate the total amount from session.data
    session_data = json.loads(session.data)  # Convert JSON string to Python list of dictionaries
    total_amount = sum(item['price'] * item['quantity'] for item in session_data)  # Calculate total

        # Add a new bill to the Bills table
    new_bill = Bill(
            table_id=table_id,
            owner_id=owner_id,
            waiter_id=session.waiter_id,
            total_amount=total_amount,  
            details=session.data 
    )

    db.session.add(new_bill)

    # Delete the session
    db.session.delete(session)
    db.session.commit()

    return jsonify({'message': f'Table {table_id} is now free, and the bill has been saved.'}), 200

@app.route('/view_bill_page', methods=['GET'])
@login_required
def view_bill_page():
    if not isinstance(current_user, Owner) and  not isinstance(current_user, Waiter):
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403
    return render_template('view_bills.html',owner_id=current_user.owner_id)

@app.route('/view_bills', methods=['GET'])
@login_required
def view_bills():
    owner_id = request.args.get('owner_id')
    bill_id = request.args.get('bill_id')  # Optional
    bill_date = request.args.get('bill_date')  # Optional (format: YYYY-MM-DD)

    query = Bill.query.filter_by(owner_id=owner_id)

    if bill_id:
        query = query.filter_by(bill_id=bill_id)

    if bill_date:
        query = query.filter(db.func.date(Bill.bill_date) == bill_date)

    bills = query.all()

    bills_data = [
        {
            'bill_id': bill.bill_id,
            'table_id': bill.table_id,
            'waiter_id': bill.waiter_id,
            'total_amount': bill.total_amount,
            'bill_date': bill.bill_date.strftime('%Y-%m-%d %H:%M:%S'),
            'details': json.loads(bill.details) if bill.details else []
        }
        for bill in bills
    ]

    return jsonify(bills_data), 200

@app.route('/todays_bills', methods=['GET'])
@login_required
def todays_bills():
    owner_id = current_user.owner_id
    today_start = datetime.combine(date.today(), datetime.min.time())  # Midnight
    today_end = datetime.combine(date.today(), datetime.max.time())    # End of day

    # Fetch today's bills and order by bill_date descending
    bills = Bill.query.filter(
        Bill.owner_id == owner_id,
        Bill.bill_date >= today_start,
        Bill.bill_date <= today_end
    ).order_by(Bill.bill_date.desc()).all()  # Newest bill comes first

    # Convert details to JSON if stored as a string
    for bill in bills:
        if isinstance(bill.details, str):
            bill.details = json.loads(bill.details)

    return render_template('todays_bills.html', bills=bills)





@app.route('/submit_contact', methods=['POST'])
def submit_contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    # Store in Database
    try:
        new_contact = Contact(name=name, email=email, message=message)
        db.session.add(new_contact)
        db.session.commit()
        flash("Contact information stored successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Database error: {e}", "danger")

    # Send Email
    try:
        msg = Message(
            "New Contact Form Submission",
            sender=app.config['MAIL_USERNAME'],
            recipients=['recipient_email@gmail.com']
        )
        msg.body = f"Name: {name}\nEmail: {email}\nMessage: {message}"
        mail.send(msg)
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash(f"Email error: {e}", "danger")
        return render_template('contact_us.html')

    return render_template('contact_us.html')


@app.route('/manage_menus', methods=['GET'])
@login_required
def manage_menus():
    if not isinstance(current_user, Owner) and not isinstance(current_user, Waiter):
        # Redirect to an error page or deny access
        return render_template('error.html', title="Access Denied", message="Only owners can perform this action."), 403
    
    items_by_category = {}
    items = Items.query.filter_by(owner_id=current_user.owner_id).all()
    for item in items:
        if item.category not in items_by_category:
            items_by_category[item.category] = []
        items_by_category[item.category].append(item)
    return render_template('manage_menu.html', items=items, items_by_category=items_by_category)

@app.route('/manage_waiters')
@login_required
def manage_waiters():
    # Check if the current user is an Owner
    if current_user.is_owner:
        waiters = Waiter.query.filter_by(owner_id=current_user.owner_id).all()
        return render_template('manage_waiters.html', waiters=waiters)
    return redirect(url_for('index'))  # Redirect if not an Owner

@app.route('/remove_waiter/<int:waiter_id>', methods=['POST'])
@login_required
def remove_waiter(waiter_id):
    if current_user.is_owner:
        waiter = Waiter.query.get_or_404(waiter_id)
        db.session.delete(waiter)
        db.session.commit()
        return redirect(url_for('manage_waiters'))
    return redirect(url_for('index'))

@app.route('/payment', methods=['GET'])
@login_required
def payment_page():
   return render_template('payment_page.html')

@app.route('/create_checkout_session', methods=['POST'])
def create_checkout_session():
    try:
        YOUR_DOMAIN = "http://localhost:5000"  # Replace with your local or frontend URL
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price': 'prod_RbYLtBCk9zeiWp',  # Replace with your Test Price ID
                    'quantity': 1
                }
            ],
            mode="subscription",
            success_url=YOUR_DOMAIN + "/success.html",
            cancel_url=YOUR_DOMAIN + "/cancel.html",
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError:
        return jsonify({'message': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'message': 'Invalid signature'}), 400

    event_type = event['type']
    event_data = event['data']['object']

    # Save the event in the Event table
    new_event = Event(
        event_id=event['id'],
        event_type=event_type,
        event_data=event_data
    )
    db.session.add(new_event)

    # Handle subscription-related events
    if event_type == 'checkout.session.completed':
        subscription_id = event_data.get('subscription')
        customer_email = event_data['customer_details'].get('email')
        customer_name = event_data['customer_details'].get('name')
        
        if subscription_id and (customer_email or customer_name):
            # Find the owner by email or name
            owner = Owner.query.filter((Owner.email == customer_email) | (Owner.owner_name == customer_name)).first()
            
            if owner:
                # Check if a subscription already exists for this owner
                existing_subscription = Subscription.query.filter(
                    (Subscription.owner_email == customer_email) | (Subscription.owner_name == customer_name)
                ).first()
                
                if existing_subscription:
                    # Update existing subscription
                    existing_subscription.status = 'active'
                    
                    existing_subscription.start_date = datetime.now(timezone.utc)
                    existing_subscription.end_date = datetime.now(timezone.utc) + timedelta(days=30)
                    print(f"Subscription updated for {customer_name} ({customer_email})")
                else:
                    # Create new subscription if none exists
                    new_subscription = Subscription(
                        
                        owner_id=owner.owner_id,
                        owner_name=customer_name,
                        owner_email=customer_email,
                        status='active',
                        start_date=datetime.now(timezone.utc),
                        end_date=datetime.now(timezone.utc) + timedelta(days=30)
                    )
                    db.session.add(new_subscription)
                    print(f"Subscription created for {customer_name} ({customer_email})")
    
    db.session.commit()
    return jsonify({'status': 'success'}), 200


if __name__ == '__main__':
    app.run(debug=True)
     