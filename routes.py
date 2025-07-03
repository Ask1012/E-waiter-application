from flask import render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail
import stripe, json
from datetime import datetime, date
from config import Config
from database import db, bcrypt
from models import Owner, User, Waiter, Items, TableSession, Bill, Subscription, Contact, Event,Owner_profile
from itsdangerous import URLSafeTimedSerializer
import qrcode,base64
from io import BytesIO
import pytz,uuid
from collections import Counter
from datetime import datetime, timedelta, timezone 
from sqlalchemy.exc import OperationalError



login_manager = LoginManager()
mail = Mail()
stripe.api_key = Config.STRIPE_SECRET_KEY
serializer = URLSafeTimedSerializer("ask")

def register_routes(app):
    """ Register routes and initialize extensions. """
    login_manager.init_app(app)
    mail.init_app(app)
        
    @login_manager.user_loader
    def load_user(user_id):
        user = Owner.query.filter_by(owner_id=user_id).first()
        if not user:
            user = Waiter.query.filter_by(waiter_id=user_id).first()
        return user

    @app.after_request
    def add_no_cache_headers(response):
        if response.content_type and 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    @app.before_request
    def check_subscriptions():
        expired_subs = Subscription.query.filter(Subscription.end_date < datetime.utcnow(), Subscription.status != "expired").all()
        for sub in expired_subs:
            sub.status = "expired"
            sub.owner.subscription_status = "expired"
        db.session.commit()
    
    @app.after_request
    def add_no_cache_headers(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.errorhandler(OperationalError)
    def handle_db_connection_error(e):
        return render_template('db_error.html'), 500
        
    @app.route('/')
    def home():
        if current_user.is_authenticated and isinstance(current_user, Owner):
            # Check subscription status
            if current_user.subscription_status == 'expired':
                flash("Your subscription has expired. Please renew.", "warning")
                return redirect(url_for('payment_page'))  # Redirect to payment page

            owner_id = current_user.owner_id
            today_start = datetime.combine(date.today(), datetime.min.time())
            today_end = datetime.combine(date.today(), datetime.max.time())

            # Fetch today's bills
            bills = Bill.query.filter(
                Bill.owner_id == owner_id,
                Bill.bill_date >= today_start,
                Bill.bill_date <= today_end
            ).order_by(Bill.bill_date.desc()).all()

            # Calculate total income today
            today_income = sum(bill.total_amount for bill in bills)

            # Track item frequencies
            item_counter = Counter()

            # Process each bill
            for bill in bills:
                if isinstance(bill.details, str):
                    try:
                        bill.details = json.loads(bill.details)  # Convert to JSON if stored as a string
                    except json.JSONDecodeError:
                        bill.details = []  # Default to an empty list if JSON decoding fails
                
                elif isinstance(bill.details, dict):  
                    # If stored as a dict, convert it to a list format
                    bill.details = [bill.details]

                elif not isinstance(bill.details, list):  
                    # If it's neither a list nor a dict, default to an empty list
                    bill.details = []

                # Count each ordered item
                for item in bill.details:
                    item_name = item.get('item_name')  # Ensure 'item_name' exists
                    quantity = item.get('quantity', 1)  # Default quantity to 1 if missing
                    if item_name:
                        item_counter[item_name] += quantity  # Increment item count

            # Get the most ordered product
            most_ordered_product = item_counter.most_common(1)  # Get the most ordered item
            most_ordered_name = most_ordered_product[0][0] if most_ordered_product else "No orders"
            most_ordered_count = most_ordered_product[0][1] if most_ordered_product else 0

            # Check if subscription exists before accessing attributes
            subscription = Subscription.query.filter_by(owner_id=current_user.owner_id).first()
            trial_days_remaining = subscription.trial_days_remaining if subscription else 0

            return render_template(
                'index.html',
                owner=current_user.owner_name,
                owner_id=owner_id,
                bills=bills,
                total_amount=today_income,
                todays_bills=len(bills),
                most_ordered_product=most_ordered_name,
                most_ordered_count=most_ordered_count,
                trial_days_remaining=trial_days_remaining
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
                    

                        trial_days = 5  # Set trial period duration
                        subscription = Subscription(
                            subscription_id=str(uuid.uuid4()),  # Ensure unique ID
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
                if bcrypt.check_password_hash(owner.password, password):
                    owner_id = serializer.dumps(owner.owner_id)
                    login_user(owner)
                    return redirect(url_for('home', owner_id=owner_id))
                else:
                    flash("Invalid password for Owner", "error")
                    return redirect(url_for('owner_login'))
            
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

        
    
    @app.route('/waiter_dashboard')
    @login_required
    def waiter_dashboard():
        if isinstance(current_user, Owner):
            return render_template('error.html', title="Access Denied", message="Only waiters can perform this action."), 403

        if isinstance(current_user, Waiter):
            items_by_category = {}
            owner = Owner.query.get(current_user.owner_id)
            owner_name = owner.owner_name if owner else "Unknown Owner"
            
            # Fetch items
            items = Items.query.filter_by(owner_id=current_user.owner_id).all() if owner else []

            # Group items by category
            for item in items:
                if item.category not in items_by_category:
                    items_by_category[item.category] = []
                items_by_category[item.category].append({
                    "item_name": item.item_name,
                    "price": item.price,
                    "id": item.item_id
                })

            waiter_id = current_user.waiter_id
            owner_id = current_user.owner_id

            # Fetch table count safely
            try:
                owner_profile = Owner_profile.query.filter_by(owner_id=owner_id).first()
                table_count = owner_profile.number_of_tables if owner_profile else 0
            except Exception:
                table_count = 0

            return render_template('waiter_dashboard.html', owner_id=owner_id, waiter_id=waiter_id, items_by_category=items_by_category, table_count=table_count)

    

    @app.route('/hotel', methods=['GET', 'POST'])
    def hotel():  
        items_by_category = {}
        owner_name = "Unknown Owner"
    
        if current_user.is_authenticated and isinstance(current_user, (User, Owner, Waiter)):
            owner = db.session.get(Owner, current_user.owner_id)
            items = Items.query.filter_by(owner_id=current_user.owner_id).all()
            owner_name = owner.owner_name if owner else "Unknown Owner"
        else:
            owner_id = request.args.get('owner_id')
            if owner_id:
                try:
                    owner_id = serializer.loads(owner_id)
                    owner = db.session.get(Owner, owner_id)
                    items = Items.query.filter_by(owner_id=owner_id).all()
                    owner_name = owner.owner_name if owner else "Unknown Owner"
                except BadSignature:
                    return render_template("error.html", title="Invalid Link", message="The link is corrupted or expired."), 400
            else:
                items = []
    
        for item in items:
            items_by_category.setdefault(item.category, []).append(item)
    
        return render_template('hotel.html', owner=owner_name, items_by_category=items_by_category)


    @app.route('/add_hotel_profile', methods=['GET', 'POST'])
    @login_required
    def add_hotel_profile():
        profile = Owner_profile.query.filter_by(owner_id=current_user.owner_id).first()

        if request.method == 'POST':
            # Get form data
            hotel_name = request.form.get('hotel_name')
            number_of_tables = request.form.get('number_of_tables')
            timezone = request.form.get('timezone', 'UTC')  # Default to UTC if not provided
            file = request.files.get('hotel_photo')

            print("Timezone received from form:", timezone)  # Debugging print

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

                # Update profile details
                profile.hotel_name = hotel_name
                profile.number_of_tables = int(number_of_tables)
                profile.timezone = timezone  # Store timezone only

                print("Profile timezone after update:", profile.timezone)  # Debugging print

                # Add to session if new, commit changes
                if profile.profile_id is None:
                    db.session.add(profile)

                db.session.commit()
                print("Timezone saved in database:", profile.timezone)  # Debugging print
                flash("Profile updated successfully!", "success")
                return redirect(url_for('add_hotel_profile'))

            except Exception as e:
                db.session.rollback()
                flash(f"Error: {str(e)}", "danger")
                return redirect(url_for('add_hotel_profile'))  # Ensure redirect even on error

        # Ensure there is always a return statement for GET requests
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
        encrypted_owner_id = serializer.dumps(owner_id)
        qr_data = url_for('hotel', owner_id=encrypted_owner_id, _external=True)



        # Generate QR Code image
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert QR code image to base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        en_owner_id = serializer.dumps(owner_id)
        return render_template('qr_display.html', qr_base64=qr_base64, owner_id=en_owner_id)

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
        waiter_id = current_user.waiter_id
        owner_id = current_user.owner_id
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

        session = TableSession.query.filter_by(table_id=table_id, owner_id=owner_id).first()
        if not session:
            return jsonify({'message': 'Table not found.'}), 404

        # Get owner's time zone from profile
        owner_profile = Owner_profile.query.filter_by(owner_id=owner_id).first()
        owner_timezone = owner_profile.timezone if owner_profile else 'UTC'

        # Convert UTC time to owner's time zone
        now_utc = datetime.now(pytz.utc)
        owner_tz = pytz.timezone(owner_timezone)
        now_local = now_utc.astimezone(owner_tz)

        session_data = json.loads(session.data)
        total_amount = sum(item['price'] * item['quantity'] for item in session_data)

        new_bill = Bill(
            table_id=table_id,
            owner_id=owner_id,
            waiter_id=session.waiter_id,
            total_amount=total_amount,
            bill_date=now_local,  # Store time in owner's time zone
            details=session.data
        )

        db.session.add(new_bill)
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
        try:
            owner_id = current_user.owner_id
            today = date.today()

            # Fetch today's bills
            bills = Bill.query.filter(
                Bill.owner_id == owner_id,
                db.func.date(Bill.bill_date) == today
            ).order_by(Bill.bill_date.desc()).all()

            print(f"Fetched {len(bills)} bills for today")  # Debugging

            # Convert details from string to JSON
            for bill in bills:
                if isinstance(bill.details, str):
                    bill.details = json.loads(bill.details) if bill.details else []

            return render_template('todays_bills.html', bills=bills)

        except Exception as e:
            print(f"Error fetching today's bills: {str(e)}")
            return jsonify({"error": "Internal Server Error"}), 500




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
            event = stripe.Webhook.construct_event(payload, sig_header, Config.STRIPE_WEBHOOK_SECRET)
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

