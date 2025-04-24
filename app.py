from flask import Flask, request, session, redirect, url_for, render_template, flash
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv

# ---------------------------------------
# Load Environment Variables
# ---------------------------------------
if not load_dotenv():
    print("Warning: .env file not loaded. Make sure it exists for environment configuration.")

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'temporary_key_for_development')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# DynamoDB Table Names
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'UsersTable')
SERVICES_TABLE_NAME = os.environ.get('SERVICES_TABLE_NAME', 'ServicesTable')
RENTALS_TABLE_NAME = os.environ.get('RENTALS_TABLE_NAME', 'RentalsTable')
TRIPS_TABLE_NAME = os.environ.get('TRIPS_TABLE_NAME', 'TripsTable')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources Initialization
# ---------------------------------------
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
    sns = boto3.client('sns', region_name=AWS_REGION_NAME)
    
    user_table = dynamodb.Table(USERS_TABLE_NAME)
    service_table = dynamodb.Table(SERVICES_TABLE_NAME)
    rental_table = dynamodb.Table(RENTALS_TABLE_NAME)
    trip_table = dynamodb.Table(TRIPS_TABLE_NAME)

except Exception as e:
    print(f"Error initializing AWS resources: {e}")
    raise

# ---------------------------------------
# Logging Configuration
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        response = user_table.get_item(Key={'email': email})
        return response.get('Item', {}).get('role')
    except Exception as e:
        logger.error(f"Error fetching role for {email}: {e}")
        return None

def send_email(to_email, subject, body):
    if not ENABLE_EMAIL:
        logger.info(f"[Email Disabled] Would send: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        logger.info(f"Email sent to {to_email}")

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")

def publish_to_sns(message, subject="RoadBuddy Notification"):
    if not ENABLE_SNS:
        logger.info(f"[SNS Disabled] Would publish: {message}")
        return

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published with MessageId: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Failed to publish SNS: {e}")

# -------------------------------
# Routes
# -------------------------------

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# About Page
@app.route('/about')
def about():
    return render_template('about.html')

# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        if not name or not email or not message:
            flash('Please fill all required fields', 'danger')
            return render_template('contact.html')
            
        try:
            # Store the contact message in DynamoDB (optional)
            # Send email notification
            contact_msg = f"New Contact Form Submission\n\nName: {name}\nEmail: {email}\nMessage:\n{message}"
            if ENABLE_EMAIL:
                send_email(SENDER_EMAIL, "New Contact Form Submission", contact_msg)
            
            # Notify via SNS
            if ENABLE_SNS:
                publish_to_sns(contact_msg, "New Contact Form - RoadBuddy")
                
            flash('Your message has been sent. We will get back to you soon!', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            logger.error(f"Contact form error: {e}")
            flash('There was an error sending your message. Please try again later.', 'danger')
    
    return render_template('contact.html')

# Register User (Provider/Customer)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():  # Check if already logged in
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Form validation
        required_fields = ['name', 'email', 'password', 'phone', 'role']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('register.html')
        
        # Check if passwords match
        if request.form['password'] != request.form['confirm_password']:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])  # Hash password
        phone = request.form['phone']
        role = request.form['role']  # 'provider' or 'customer'
        
        # Check if user already exists
        existing_user = user_table.get_item(Key={'email': email}).get('Item')
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html')

        # Add user to DynamoDB
        user_item = {
            'email': email,
            'name': name,
            'password': password,  # Store hashed password
            'phone': phone,
            'role': role,
            'created_at': datetime.now().isoformat(),
        }
        
        # Add service types only for providers
        if role == 'provider' and 'service_types' in request.form:
            service_types = request.form.getlist('service_types')
            user_item['service_types'] = service_types
            
            # Add location for providers
            if 'location' in request.form:
                user_item['location'] = request.form['location']
        
        user_table.put_item(Item=user_item)
        
        # Send welcome email if enabled
        if ENABLE_EMAIL:
            welcome_msg = f"Welcome to RoadBuddy, {name}! Your account has been created successfully."
            send_email(email, "Welcome to RoadBuddy", welcome_msg)
        
        # Send admin notification via SNS if configured
        if ENABLE_SNS:
            sns_msg = f'New user registered: {name} ({email}) as {role}'
            publish_to_sns(sns_msg, 'New User Registration - RoadBuddy')
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login User (Provider/Customer)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():  # If the user is already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if not request.form.get('email') or not request.form.get('password'):
            flash('All fields are required', 'danger')
            return render_template('login.html')
            
        email = request.form['email']
        password = request.form['password']

        # Validate user credentials
        user = user_table.get_item(Key={'email': email}).get('Item')

        if user:
            # Check password
            if check_password_hash(user['password'], password):  # Use check_password_hash to verify hashed password
                session['email'] = email
                session['role'] = user['role']  # Store the role in the session
                session['name'] = user.get('name', '')
                
                # Update login count (optional)
                try:
                    user_table.update_item(
                        Key={'email': email},
                        UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc',
                        ExpressionAttributeValues={':inc': 1, ':zero': 0}
                    )
                except Exception as e:
                    logger.error(f"Failed to update login count: {e}")
                
                flash('Login successful.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.', 'danger')
        else:
            flash('Email not found.', 'danger')

    return render_template('login.html')

# Logout User
@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('role', None)
    session.pop('name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# Dashboard for both Providers and Customers
@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))

    role = session['role']
    email = session['email']

    if role == 'provider':
        # Fetch all service requests assigned to this provider
        try:
            response = service_table.query(
                IndexName='ProviderEmailIndex',
                KeyConditionExpression="provider_email = :email",
                ExpressionAttributeValues={":email": email}
            )
            service_requests = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch service requests: {e}")
            # Fallback to scan if GSI is not yet created
            try:
                response = service_table.scan(
                    FilterExpression="provider_email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                service_requests = response.get('Items', [])
            except Exception as ex:
                logger.error(f"Fallback scan failed: {ex}")
                service_requests = []
                
        # Fetch vehicle rentals managed by this provider
        try:
            response = rental_table.query(
                IndexName='ProviderEmailIndex',
                KeyConditionExpression="provider_email = :email",
                ExpressionAttributeValues={":email": email}
            )
            rentals = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch rentals: {e}")
            # Fallback to scan
            try:
                response = rental_table.scan(
                    FilterExpression="provider_email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                rentals = response.get('Items', [])
            except Exception as ex:
                logger.error(f"Fallback scan failed: {ex}")
                rentals = []
        
        return render_template('provider_dashboard.html', 
                              service_requests=service_requests, 
                              rentals=rentals)

    elif role == 'customer':
        # Fetch customer's service requests
        try:
            response = service_table.query(
                IndexName='CustomerEmailIndex',
                KeyConditionExpression="customer_email = :email",
                ExpressionAttributeValues={":email": email}
            )
            service_requests = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch service requests: {e}")
            # Fallback to scan
            try:
                response = service_table.scan(
                    FilterExpression="customer_email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                service_requests = response.get('Items', [])
            except Exception as ex:
                logger.error(f"Fallback scan failed: {ex}")
                service_requests = []
        
        # Fetch customer's rental bookings
        try:
            response = rental_table.query(
                IndexName='CustomerEmailIndex',
                KeyConditionExpression="customer_email = :email",
                ExpressionAttributeValues={":email": email}
            )
            rentals = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch rentals: {e}")
            # Fallback to scan
            try:
                response = rental_table.scan(
                    FilterExpression="customer_email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                rentals = response.get('Items', [])
            except Exception as ex:
                logger.error(f"Fallback scan failed: {ex}")
                rentals = []
        
        # Fetch customer's trip bookings
        try:
            response = trip_table.query(
                IndexName='CustomerEmailIndex',
                KeyConditionExpression="customer_email = :email",
                ExpressionAttributeValues={":email": email}
            )
            trips = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch trips: {e}")
            # Fallback to scan
            try:
                response = trip_table.scan(
                    FilterExpression="customer_email = :email",
                    ExpressionAttributeValues={":email": email}
                )
                trips = response.get('Items', [])
            except Exception as ex:
                logger.error(f"Fallback scan failed: {ex}")
                trips = []
        
        # Get list of service providers for requesting services
        try:
            provider_response = user_table.scan(
                FilterExpression="#role = :role",
                ExpressionAttributeNames={"#role": "role"},
                ExpressionAttributeValues={":role": 'provider'}
            )
            providers = provider_response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to fetch providers: {e}")
            providers = []
        
        return render_template('customer_dashboard.html', 
                              service_requests=service_requests, 
                              rentals=rentals,
                              trips=trips,
                              providers=providers)

# Request Emergency Service (Customer)
@app.route('/request_service', methods=['GET', 'POST'])
def request_service():
    if not is_logged_in() or session['role'] != 'customer':
        flash('Only customers can request services.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Form validation
        required_fields = ['service_type', 'location', 'description']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return redirect(url_for('request_service'))
            
        service_type = request.form['service_type']
        location = request.form['location']
        description = request.form['description']
        provider_email = request.form.get('provider_email', '')  # Optional if customer selects specific provider
        
        customer_email = session['email']
        customer_name = session['name']
        
        # Get provider information if specified
        provider_name = "Unassigned"
        if provider_email:
            try:
                provider = user_table.get_item(Key={'email': provider_email}).get('Item', {})
                provider_name = provider.get('name', 'Service Provider')
            except Exception as e:
                logger.error(f"Failed to fetch provider info: {e}")
        
        # Create a new service request
        service_id = str(uuid.uuid4())
        service_item = {
            'service_id': service_id,
            'service_type': service_type,
            'customer_email': customer_email,
            'customer_name': customer_name,
            'location': location,
            'description': description,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
        }
        
        # Add provider info if specified
        if provider_email:
            service_item['provider_email'] = provider_email
            service_item['provider_name'] = provider_name
        
        service_table.put_item(Item=service_item)
        
        # Send email notifications if enabled
        if ENABLE_EMAIL:
            if provider_email:
                # Send email notification to provider
                provider_msg = f"Dear {provider_name},\n\nA new service request has been created by {customer_name}.\n\nType: {service_type}\nLocation: {location}\nDescription: {description}\n\nPlease login to your dashboard to view details."
                send_email(provider_email, f"New {service_type} Service Request", provider_msg)
            
            # Send confirmation email to customer
            customer_msg = f"Dear {customer_name},\n\nYour service request for {service_type} has been created successfully.\n\nLocation: {location}\n\nWe'll notify you once a service provider accepts your request."
            send_email(customer_email, "Service Request Confirmation", customer_msg)
        
        # Send SNS notification if configured
        if ENABLE_SNS:
            sns_msg = f'New service request: {service_type} by {customer_name} at {location}'
            publish_to_sns(sns_msg, 'New Service Request - RoadBuddy')
        
        flash('Service request created successfully. Help is on the way!', 'success')
        return redirect(url_for('dashboard'))
    
    # Get list of service providers for selection
    try:
        response = user_table.scan(
            FilterExpression="#role = :role",
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={":role": 'provider'}
        )
        providers = response.get('Items', [])
    except Exception as e:
        logger.error(f"Failed to fetch providers: {e}")
        providers = []
    
    return render_template('request_service.html', providers=providers)

# Book a Vehicle Rental (Customer)
@app.route('/book_rental', methods=['GET', 'POST'])
def book_rental():
    if not is_logged_in() or session['role'] != 'customer':
        flash('Only customers can book rentals.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Form validation
        required_fields = ['vehicle_type', 'pickup_date', 'dropoff_date', 'pickup_location']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return redirect(url_for('book_rental'))
            
        vehicle_type = request.form['vehicle_type']
        pickup_date = request.form['pickup_date']
        dropoff_date = request.form['dropoff_date']
        pickup_location = request.form['pickup_location']
        provider_email = request.form.get('provider_email', '')  # Optional
        
        customer_email = session['email']
        customer_name = session['name']
        
        # Create a new rental booking
        rental_id = str(uuid.uuid4())
        rental_item = {
            'rental_id': rental_id,
            'vehicle_type': vehicle_type,
            'customer_email': customer_email,
            'customer_name': customer_name,
            'pickup_location': pickup_location,
            'pickup_date': pickup_date,
            'dropoff_date': dropoff_date,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
        }
        
        # Add provider info if specified
        if provider_email:
            # Get provider name
            try:
                provider = user_table.get_item(Key={'email': provider_email}).get('Item', {})
                provider_name = provider.get('name', 'Rental Provider')
                rental_item['provider_email'] = provider_email
                rental_item['provider_name'] = provider_name
            except Exception as e:
                logger.error(f"Failed to fetch provider info: {e}")
        
        rental_table.put_item(Item=rental_item)
        
        # Send email notifications if enabled
        if ENABLE_EMAIL:
            if provider_email:
                # Send email notification to provider
                provider_msg = f"Dear {provider_name},\n\nA new rental booking has been made by {customer_name}.\n\nVehicle Type: {vehicle_type}\nPickup Date: {pickup_date}\nDropoff Date: {dropoff_date}\nLocation: {pickup_location}\n\nPlease login to your dashboard to confirm this booking."
                send_email(provider_email, "New Vehicle Rental Booking", provider_msg)
            
            # Send confirmation email to customer
            customer_msg = f"Dear {customer_name},\n\nYour rental booking for a {vehicle_type} has been submitted successfully.\n\nPickup: {pickup_date} at {pickup_location}\nDropoff: {dropoff_date}\n\nWe'll notify you once your booking is confirmed."
            send_email(customer_email, "Rental Booking Confirmation", customer_msg)
        
        flash('Rental booking created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Get list of rental providers for selection
    try:
        response = user_table.scan(
            FilterExpression="#role = :role AND contains(service_types, :rental)",
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={":role": 'provider', ":rental": 'rental'}
        )
        providers = response.get('Items', [])
    except Exception as e:
        logger.error(f"Failed to fetch rental providers: {e}")
        providers = []
    
    return render_template('book_rental.html', providers=providers)

# Book a Trip (Customer)
@app.route('/book_trip', methods=['GET', 'POST'])
def book_trip():
    if not is_logged_in() or session['role'] != 'customer':
        flash('Only customers can book trips.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Form validation
        required_fields = ['destination', 'start_date', 'end_date', 'num_people']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return redirect(url_for('book_trip'))
            
        destination = request.form['destination']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        num_people = request.form['num_people']
        trip_type = request.form.get('trip_type', 'Standard')
        special_requests = request.form.get('special_requests', '')
        
        customer_email = session['email']
        customer_name = session['name']
        
        # Create a new trip booking
        trip_id = str(uuid.uuid4())
        trip_item = {
            'trip_id': trip_id,
            'destination': destination,
            'customer_email': customer_email,
            'customer_name': customer_name,
            'start_date': start_date,
            'end_date': end_date,
            'num_people': num_people,
            'trip_type': trip_type,
            'special_requests': special_requests,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
        }
        
        trip_table.put_item(Item=trip_item)
        
        # Send confirmation email to customer if enabled
        if ENABLE_EMAIL:
            customer_msg = f"Dear {customer_name},\n\nYour trip booking to {destination} has been created successfully.\n\nDates: {start_date} to {end_date}\nPeople: {num_people}\nType: {trip_type}\n\nWe'll notify you once your booking is confirmed."
            send_email(customer_email, "Trip Booking Confirmation", customer_msg)
        
        # Send SNS notification if configured
        if ENABLE_SNS:
            sns_msg = f'New trip booking: {customer_name} to {destination} from {start_date} to {end_date}'
            publish_to_sns(sns_msg, 'New Trip Booking - RoadBuddy')
        
        flash('Trip booking created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('book_trip.html')

# View Service Request Details
@app.route('/service_details/<service_id>', methods=['GET', 'POST'])
def service_details(service_id):
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))

    # Fetch service request details
    try:
        response = service_table.get_item(Key={'service_id': service_id})
        service = response.get('Item')
        
        if not service:
            flash('Service request not found.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Security check - verify the logged-in user should access this service
        if session['role'] == 'provider' and service.get('provider_email') != session['email']:
            flash('You are not authorized to view this service request.', 'danger')
            return redirect(url_for('dashboard'))
        elif session['role'] == 'customer' and service['customer_email'] != session['email']:
            flash('You are not authorized to view this service request.', 'danger')
            return redirect(url_for('dashboard'))

        # For Provider: Update service status
        if request.method == 'POST' and session['role'] == 'provider':
            action = request.form.get('action')
            status_update = None
            
            if action == 'accept':
                status_update = 'accepted'
            elif action == 'complete':
                status_update = 'completed'
            elif action == 'cancel':
                status_update = 'cancelled'
            
            if status_update:
                # Update service status
                service_table.update_item(
                    Key={'service_id': service_id},
                    UpdateExpression="SET #status = :s, updated_at = :u",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ':s': status_update,
                        ':u': datetime.now().isoformat()
                    }
                )
                
                # If service is being completed, add cost and notes
                if status_update == 'completed' and 'cost' in request.form:
                    service_table
                    service_table.update_item(
                        Key={'service_id': service_id},
                        UpdateExpression="SET cost = :c, service_notes = :n",
                        ExpressionAttributeValues={
                            ':c': request.form.get('cost', '0'),
                            ':n': request.form.get('service_notes', '')
                        }
                    )
                
                # Send email notification to customer if enabled
                if ENABLE_EMAIL:
                    customer_email = service['customer_email']
                    customer_name = service.get('customer_name', 'Customer')
                    provider_name = session.get('name', 'Service Provider')
                    service_type = service.get('service_type', 'service')
                    
                    customer_msg = f"Dear {customer_name},\n\nYour {service_type} request has been {status_update} by {provider_name}."
                    
                    if status_update == 'completed':
                        cost = request.form.get('cost', 'N/A')
                        notes = request.form.get('service_notes', 'No additional notes.')
                        customer_msg += f"\n\nService Cost: ${cost}\nService Notes: {notes}\n\nThank you for using RoadBuddy!"
                    
                    send_email(customer_email, f"Service Request {status_update.capitalize()}", customer_msg)
                
                flash(f'Service request {status_update} successfully.', 'success')
                return redirect(url_for('dashboard'))

        # Determine which template to render based on user role
        if session['role'] == 'provider':
            return render_template('service_details_provider.html', service=service)
        else:  # customer
            return render_template('service_details_customer.html', service=service)
    except Exception as e:
        logger.error(f"Error in service_details: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# View Rental Details
@app.route('/rental_details/<rental_id>', methods=['GET', 'POST'])
def rental_details(rental_id):
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))

    # Fetch rental details
    try:
        response = rental_table.get_item(Key={'rental_id': rental_id})
        rental = response.get('Item')
        
        if not rental:
            flash('Rental booking not found.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Security check - verify the logged-in user should access this rental
        if session['role'] == 'provider' and rental.get('provider_email') != session['email']:
            flash('You are not authorized to view this rental booking.', 'danger')
            return redirect(url_for('dashboard'))
        elif session['role'] == 'customer' and rental['customer_email'] != session['email']:
            flash('You are not authorized to view this rental booking.', 'danger')
            return redirect(url_for('dashboard'))

        # For Provider: Update rental status
        if request.method == 'POST' and session['role'] == 'provider':
            action = request.form.get('action')
            status_update = None
            
            if action == 'confirm':
                status_update = 'confirmed'
            elif action == 'complete':
                status_update = 'completed'
            elif action == 'cancel':
                status_update = 'cancelled'
            
            if status_update:
                # Update rental booking status
                rental_table.update_item(
                    Key={'rental_id': rental_id},
                    UpdateExpression="SET #status = :s, updated_at = :u",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ':s': status_update,
                        ':u': datetime.now().isoformat()
                    }
                )
                
                # If rental is being confirmed, add vehicle details
                if status_update == 'confirmed' and 'vehicle_id' in request.form:
                    rental_table.update_item(
                        Key={'rental_id': rental_id},
                        UpdateExpression="SET vehicle_id = :v, vehicle_details = :d, rental_cost = :c",
                        ExpressionAttributeValues={
                            ':v': request.form.get('vehicle_id', ''),
                            ':d': request.form.get('vehicle_details', ''),
                            ':c': request.form.get('rental_cost', '0')
                        }
                    )
                
                # Send email notification to customer if enabled
                if ENABLE_EMAIL:
                    customer_email = rental['customer_email']
                    customer_name = rental.get('customer_name', 'Customer')
                    provider_name = session.get('name', 'Rental Provider')
                    vehicle_type = rental.get('vehicle_type', 'vehicle')
                    
                    customer_msg = f"Dear {customer_name},\n\nYour {vehicle_type} rental booking has been {status_update} by {provider_name}."
                    
                    if status_update == 'confirmed':
                        vehicle_details = request.form.get('vehicle_details', 'No details provided')
                        cost = request.form.get('rental_cost', 'N/A')
                        customer_msg += f"\n\nVehicle Details: {vehicle_details}\nRental Cost: ${cost}\n\nThank you for choosing RoadBuddy!"
                    
                    send_email(customer_email, f"Rental Booking {status_update.capitalize()}", customer_msg)
                
                flash(f'Rental booking {status_update} successfully.', 'success')
                return redirect(url_for('dashboard'))

        # Determine which template to render based on user role
        if session['role'] == 'provider':
            return render_template('rental_details_provider.html', rental=rental)
        else:  # customer
            return render_template('rental_details_customer.html', rental=rental)
    except Exception as e:
        logger.error(f"Error in rental_details: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# View Trip Details
@app.route('/trip_details/<trip_id>', methods=['GET', 'POST'])
def trip_details(trip_id):
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))

    # Fetch trip details
    try:
        response = trip_table.get_item(Key={'trip_id': trip_id})
        trip = response.get('Item')
        
        if not trip:
            flash('Trip booking not found.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Security check - verify the logged-in user should access this trip
        if session['role'] == 'customer' and trip['customer_email'] != session['email']:
            flash('You are not authorized to view this trip booking.', 'danger')
            return redirect(url_for('dashboard'))

        # For admin (future feature): Update trip status
        if request.method == 'POST' and session.get('role') == 'admin':
            # Add admin functionality here
            pass

        # For now, only customer view is needed
        return render_template('trip_details.html', trip=trip)
    except Exception as e:
        logger.error(f"Error in trip_details: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# Order Food (Customer)
@app.route('/order_food', methods=['GET', 'POST'])
def order_food():
    if not is_logged_in() or session['role'] != 'customer':
        flash('Only customers can order food.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Form validation
        required_fields = ['food_items', 'delivery_location']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return redirect(url_for('order_food'))
            
        food_items = request.form['food_items']
        delivery_location = request.form['delivery_location']
        special_instructions = request.form.get('special_instructions', '')
        
        customer_email = session['email']
        customer_name = session['name']
        
        # Create a new food order (using the service table)
        order_id = str(uuid.uuid4())
        order_item = {
            'service_id': order_id,
            'service_type': 'food_delivery',
            'customer_email': customer_email,
            'customer_name': customer_name,
            'location': delivery_location,
            'description': f"Food items: {food_items}. Special instructions: {special_instructions}",
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
        }
        
        service_table.put_item(Item=order_item)
        
        # Send confirmation email to customer if enabled
        if ENABLE_EMAIL:
            customer_msg = f"Dear {customer_name},\n\nYour food order has been placed successfully.\n\nItems: {food_items}\nDelivery Location: {delivery_location}\n\nWe'll notify you once your order is confirmed."
            send_email(customer_email, "Food Order Confirmation", customer_msg)
        
        # Send SNS notification if configured
        if ENABLE_SNS:
            sns_msg = f'New food order from {customer_name} to be delivered at {delivery_location}'
            publish_to_sns(sns_msg, 'New Food Order - RoadBuddy')
        
        flash('Food order placed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('order_food.html')

# User profile page
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))
    
    email = session['email']
    try:
        user = user_table.get_item(Key={'email': email}).get('Item', {})
        
        if request.method == 'POST':
            # Update user profile
            name = request.form.get('name')
            phone = request.form.get('phone')
            
            update_expression = "SET #name = :name, phone = :phone"
            expression_values = {
                ':name': name,
                ':phone': phone
            }
            
            # Update additional fields based on user role
            if session['role'] == 'provider':
                if 'service_types' in request.form:
                    service_types = request.form.getlist('service_types')
                    update_expression += ", service_types = :st"
                    expression_values[':st'] = service_types
                
                if 'location' in request.form:
                    update_expression += ", #loc = :loc"
                    expression_values[':loc'] = request.form['location']
                    # Add location to expression names due to potential reserved word
                    expression_names = {'#name': 'name', '#loc': 'location'}
                else:
                    expression_names = {'#name': 'name'}
            else:
                expression_names = {'#name': 'name'}
            
            user_table.update_item(
                Key={'email': email},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames=expression_names
            )
            
            # Update session name
            session['name'] = name
            
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))
        
        return render_template('profile.html', user=user)
    except Exception as e:
        logger.error(f"Profile error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# Add Vehicle (Provider)
@app.route('/add_vehicle', methods=['GET', 'POST'])
def add_vehicle():
    if not is_logged_in() or session['role'] != 'provider':
        flash('Only service providers can add vehicles.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Form validation
        required_fields = ['vehicle_type', 'model', 'year', 'license_plate', 'rental_rate']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('add_vehicle.html')
        
        vehicle_type = request.form['vehicle_type']
        model = request.form['model']
        year = request.form['year']
        license_plate = request.form['license_plate']
        rental_rate = request.form['rental_rate']
        description = request.form.get('description', '')
        
        provider_email = session['email']
        provider_name = session['name']
        
        # Create a new vehicle entry in DynamoDB (we'll create a vehicles table if needed)
        vehicle_id = str(uuid.uuid4())
        vehicle_item = {
            'vehicle_id': vehicle_id,
            'provider_email': provider_email,
            'provider_name': provider_name,
            'vehicle_type': vehicle_type,
            'model': model,
            'year': year,
            'license_plate': license_plate,
            'rental_rate': rental_rate,
            'description': description,
            'status': 'available',
            'created_at': datetime.now().isoformat(),
        }
        
        # Check if vehicle table exists, if not we'll add to the user's profile instead
        try:
            vehicle_table = dynamodb.Table('VehiclesTable')
            vehicle_table.put_item(Item=vehicle_item)
            
            flash('Vehicle added successfully.', 'success')
        except Exception as e:
            logger.error(f"Failed to add vehicle to vehicle table: {e}")
            # Fallback: Add vehicle to user profile (as an array of vehicles)
            try:
                user_table.update_item(
                    Key={'email': provider_email},
                    UpdateExpression="SET vehicles = list_append(if_not_exists(vehicles, :empty_list), :vehicle)",
                    ExpressionAttributeValues={
                        ':empty_list': [],
                        ':vehicle': [vehicle_item]
                    }
                )
                flash('Vehicle added to your profile successfully.', 'success')
            except Exception as ex:
                logger.error(f"Failed to add vehicle to user profile: {ex}")
                flash('Failed to add vehicle. Please try again later.', 'danger')
        
        return redirect(url_for('dashboard'))
    
    return render_template('add_vehicle.html')

# Search functionality 
@app.route('/search', methods=['GET', 'POST'])
def search():
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        search_term = request.form.get('search_term', '')
        search_type = request.form.get('search_type', 'all')
        
        if not search_term:
            flash('Please enter a search term.', 'warning')
            return redirect(url_for('dashboard'))
        
        try:
            results = {}
            
            # Search based on user role and search type
            if search_type == 'all' or search_type == 'services':
                if session['role'] == 'provider':
                    # Providers search their service requests
                    response = service_table.scan(
                        FilterExpression="provider_email = :email AND (contains(customer_name, :search) OR contains(service_type, :search) OR contains(#status, :search))",
                        ExpressionAttributeNames={"#status": "status"},
                        ExpressionAttributeValues={
                            ":email": session['email'],
                            ":search": search_term
                        }
                    )
                else:  # customer
                    # Customers search their service requests
                    response = service_table.scan(
                        FilterExpression="customer_email = :email AND (contains(service_type, :search) OR contains(#status, :search))",
                        ExpressionAttributeNames={"#status": "status"},
                        ExpressionAttributeValues={
                            ":email": session['email'],
                            ":search": search_term
                        }
                    )
                
                results['services'] = response.get('Items', [])
            
            if search_type == 'all' or search_type == 'rentals':
                if session['role'] == 'provider':
                    # Providers search their rental bookings
                    response = rental_table.scan(
                        FilterExpression="provider_email = :email AND (contains(customer_name, :search) OR contains(vehicle_type, :search) OR contains(#status, :search))",
                        ExpressionAttributeNames={"#status": "status"},
                        ExpressionAttributeValues={
                            ":email": session['email'],
                            ":search": search_term
                        }
                    )
                else:  # customer
                    # Customers search their rental bookings
                    response = rental_table.scan(
                        FilterExpression="customer_email = :email AND (contains(vehicle_type, :search) OR contains(#status, :search))",
                        ExpressionAttributeNames={"#status": "status"},
                        ExpressionAttributeValues={
                            ":email": session['email'],
                            ":search": search_term
                        }
                    )
                
                results['rentals'] = response.get('Items', [])
            
            if search_type == 'all' or search_type == 'trips' and session['role'] == 'customer':
                # Customers search their trip bookings
                response = trip_table.scan(
                    FilterExpression="customer_email = :email AND (contains(destination, :search) OR contains(#status, :search))",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":email": session['email'],
                        ":search": search_term
                    }
                )
                
                results['trips'] = response.get('Items', [])
            
            return render_template('search_results.html', results=results, search_term=search_term)
        except Exception as e:
            logger.error(f"Search failed: {e}")
            flash('Search failed. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

# Health check endpoint for AWS load balancers
@app.route('/health')
def health():
    return {'status': 'healthy'}, 200

# -------------------------------
# Run the Flask app
# -------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)