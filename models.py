from database import db
from flask_login import UserMixin
from datetime import datetime, timezone
import json

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
    timezone = db.Column(db.String(50), default='UTC')
        # Relationship to Owner
    owner = db.relationship('Owner', back_populates='owner_profiles')

    @property
    def hotel_details(self):
        return f"Hotel: {self.hotel_name}, Tables: {self.number_of_tables}"

class Waiter(db.Model, UserMixin):
        __tablename__ = 'waiters'
        waiter_id = db.Column(db.Integer, primary_key=True)
        waiter_name = db.Column(db.String(50), nullable=False)
        password = db.Column(db.String(255), nullable=False)
        owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
        joined_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

        # Define relationships
        owner = db.relationship('Owner', back_populates='waiters')
        bills = db.relationship('Bill', back_populates='waiter', cascade="all, delete-orphan")
        table_sessions = db.relationship('TableSession', back_populates='waiter', cascade="all, delete-orphan")  # ✅ Added relationship

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
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    waiter_id = db.Column(db.Integer, db.ForeignKey('waiters.waiter_id'), nullable=False)  # ✅ Keep only this one
    status = db.Column(db.Enum('free', 'occupied', name='status_enum'), default='occupied', nullable=False)
    data = db.Column(db.Text, nullable=True, default=json.dumps([]))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total = db.Column(db.Integer, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship('Owner', back_populates='table_sessions')
    waiter = db.relationship('Waiter', back_populates='table_sessions')  # ✅ Keep the relationship


class Bill(db.Model):
    __tablename__ = 'bills'

    bill_id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id'), nullable=False)
    waiter_id = db.Column(db.Integer, db.ForeignKey('waiters.waiter_id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    bill_date = db.Column(db.DateTime, default=datetime.now)
    details = db.Column(db.JSON, nullable=True)  # Change to JSON for direct storage

    owner = db.relationship('Owner', back_populates='bills')
    waiter = db.relationship('Waiter', back_populates='bills')

    def get_details(self):
        """Ensures 'details' is always returned as a dictionary"""
        if isinstance(self.details, str):
            try:
                return json.loads(self.details)  # Convert string to JSON
            except json.JSONDecodeError:
                return {}
        return self.details if isinstance(self.details, dict) else {}


class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    subscription_id = db.Column(db.String(36), primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('hotel_owners.owner_id', ondelete='CASCADE'), nullable=False)
    owner_name = db.Column(db.String(255), nullable=False)  
    owner_email = db.Column(db.String(255), nullable=False, unique=True)  
    status = db.Column(db.Enum('trial', 'active', 'expired', name='subscription_status'), default='trial', nullable=False)
    start_date = db.Column(db.DateTime, nullable=True)  
    end_date = db.Column(db.DateTime, nullable=True) 

    owner = db.relationship('Owner', back_populates='subscription')

    def is_expired(self):
        return self.end_date and datetime.utcnow() > self.end_date  
    

    @property
    def trial_days_remaining(self):
        """Returns the number of days remaining in the trial period."""
        if self.end_date:
            remaining = (self.end_date - datetime.utcnow()).days
            return max(0, remaining)  # Ensure it never returns negative values
        return 0

    
            
# Auto-update the subscription status before any request


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(255), unique=True, nullable=False)
    event_type = db.Column(db.String(255), nullable=False)
    event_data = db.Column(db.JSON, nullable=False)
