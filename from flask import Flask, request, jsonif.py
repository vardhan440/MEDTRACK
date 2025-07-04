from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import boto3
import logging
import os
import uuid
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# ---------------------------------------
# Load Environment Variables
# ---------------------------------------
if not load_dotenv():
    print("Warning: .env file not found. Using default configurations.")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

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
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'WellnessUsers')
ACTIVITIES_TABLE_NAME = os.environ.get('ACTIVITIES_TABLE_NAME', 'UserActivities')
HEALTH_METRICS_TABLE_NAME = os.environ.get('HEALTH_METRICS_TABLE_NAME', 'HealthMetrics')
GOALS_TABLE_NAME = os.environ.get('GOALS_TABLE_NAME', 'WellnessGoals')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# Login attempt tracking
login_attempts = {}

# ---------------------------------------
# AWS Resources Initialization
# ---------------------------------------
try:
    # Use local DynamoDB for development if AWS credentials not available
    if os.environ.get('AWS_ACCESS_KEY_ID'):
        dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
        sns = boto3.client('sns', region_name=AWS_REGION_NAME) if ENABLE_SNS else None
    else:
        # Mock DynamoDB for local development
        dynamodb = None
        sns = None
        logger.warning("AWS credentials not found. Running in local mode.")
        
except Exception as e:
    logger.error(f"Error initializing AWS resources: {e}")
    dynamodb = None
    sns = None

# ---------------------------------------
# Mock Database for Local Development
# ---------------------------------------
# Simple in-memory storage for local development
local_db = {
    'users': {},
    'activities': {},
    'health_metrics': {},
    'goals': {}
}

# ---------------------------------------
# Database Helper Functions
# ---------------------------------------
def get_user_table():
    if dynamodb:
        return dynamodb.Table(USERS_TABLE_NAME)
    return None

def get_activities_table():
    if dynamodb:
        return dynamodb.Table(ACTIVITIES_TABLE_NAME)
    return None

def get_health_metrics_table():
    if dynamodb:
        return dynamodb.Table(HEALTH_METRICS_TABLE_NAME)
    return None

def get_goals_table():
    if dynamodb:
        return dynamodb.Table(GOALS_TABLE_NAME)
    return None

# ---------------------------------------
# Authentication Decorator
# ---------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def send_email_notification(to_email, subject, body):
    if not ENABLE_EMAIL or not SENDER_EMAIL:
        logger.info(f"Email notification would be sent: {subject}")
        return True
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def send_sns_notification(message):
    if not ENABLE_SNS or not sns or not SNS_TOPIC_ARN:
        logger.info(f"SNS notification would be sent: {message}")
        return True
    
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Message=message)
        logger.info("SNS notification sent successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {e}")
        return False

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        
        if not email or not password or not name:
            return jsonify({'error': 'Email, password, and name are required'}), 400
        
        # Check if user already exists
        if dynamodb:
            user_table = get_user_table()
            try:
                response = user_table.get_item(Key={'email': email})
                if 'Item' in response:
                    return jsonify({'error': 'User already exists'}), 400
            except Exception as e:
                logger.error(f"Error checking existing user: {e}")
        else:
            # Local storage check
            if email in local_db['users']:
                return jsonify({'error': 'User already exists'}), 400
        
        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        
        user_data = {
            'user_id': user_id,
            'email': email,
            'name': name,
            'password_hash': hashed_password,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }
        
        if dynamodb:
            user_table = get_user_table()
            user_table.put_item(Item=user_data)
        else:
            local_db['users'][email] = user_data
        
        # Send welcome email
        welcome_subject = "Welcome to WellnessTracker!"
        welcome_body = f"Hi {name},\n\nWelcome to WellnessTracker! Start tracking your wellness journey today.\n\nBest regards,\nWellnessTracker Team"
        send_email_notification(email, welcome_subject, welcome_body)
        
        logger.info(f"New user registered: {email}")
        return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Rate limiting check
        client_ip = request.remote_addr
        if client_ip in login_attempts:
            if login_attempts[client_ip]['count'] >= 5:
                time_diff = datetime.now() - login_attempts[client_ip]['last_attempt']
                if time_diff < timedelta(minutes=15):
                    return jsonify({'error': 'Too many login attempts. Try again later.'}), 429
                else:
                    login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}
        
        # Get user
        user_data = None
        if dynamodb:
            user_table = get_user_table()
            try:
                response = user_table.get_item(Key={'email': email})
                if 'Item' in response:
                    user_data = response['Item']
            except Exception as e:
                logger.error(f"Error fetching user: {e}")
        else:
            user_data = local_db['users'].get(email)
        
        if not user_data:
            # Track failed attempt
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}
            login_attempts[client_ip]['count'] += 1
            login_attempts[client_ip]['last_attempt'] = datetime.now()
            
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not check_password_hash(user_data['password_hash'], password):
            # Track failed attempt
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}
            login_attempts[client_ip]['count'] += 1
            login_attempts[client_ip]['last_attempt'] = datetime.now()
            
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Reset login attempts on successful login
        if client_ip in login_attempts:
            del login_attempts[client_ip]
        
        # Create session
        session['user_id'] = user_data['user_id']
        session['email'] = user_data['email']
        session['name'] = user_data['name']
        session.permanent = True
        
        logger.info(f"User logged in: {email}")
        return jsonify({
            'message': 'Login successful',
            'user': {
                'user_id': user_data['user_id'],
                'email': user_data['email'],
                'name': user_data['name']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# ---------------------------------------
# Activity Tracking Routes
# ---------------------------------------
@app.route('/api/activities', methods=['POST'])
@login_required
def log_activity():
    try:
        data = request.get_json()
        activity_type = data.get('activity_type')  # e.g., 'running', 'cycling', 'gym'
        duration = data.get('duration')  # in minutes
        calories_burned = data.get('calories_burned')
        notes = data.get('notes', '')
        
        if not activity_type or not duration:
            return jsonify({'error': 'Activity type and duration are required'}), 400
        
        activity_id = str(uuid.uuid4())
        activity_data = {
            'activity_id': activity_id,
            'user_id': session['user_id'],
            'activity_type': activity_type,
            'duration': int(duration),
            'calories_burned': int(calories_burned) if calories_burned else 0,
            'notes': notes,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now().isoformat()
        }
        
        if dynamodb:
            activities_table = get_activities_table()
            activities_table.put_item(Item=activity_data)
        else:
            if session['user_id'] not in local_db['activities']:
                local_db['activities'][session['user_id']] = []
            local_db['activities'][session['user_id']].append(activity_data)
        
        logger.info(f"Activity logged: {activity_type} for user {session['user_id']}")
        return jsonify({'message': 'Activity logged successfully', 'activity_id': activity_id}), 201
        
    except Exception as e:
        logger.error(f"Error logging activity: {e}")
        return jsonify({'error': 'Failed to log activity'}), 500

@app.route('/api/activities', methods=['GET'])
@login_required
def get_activities():
    try:
        # Get query parameters
        limit = int(request.args.get('limit', 10))
        date_from = request.args.get('date_from')
        
        activities = []
        
        if dynamodb:
            # In a real implementation, you'd query by user_id with GSI
            # For now, using scan with filter (not recommended for production)
            activities_table = get_activities_table()
            response = activities_table.scan()
            user_activities = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_activities = local_db['activities'].get(session['user_id'], [])
        
        # Sort by timestamp (newest first)
        user_activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Apply filters
        if date_from:
            user_activities = [a for a in user_activities if a['date'] >= date_from]
        
        # Apply limit
        activities = user_activities[:limit]
        
        return jsonify({'activities': activities}), 200
        
    except Exception as e:
        logger.error(f"Error fetching activities: {e}")
        return jsonify({'error': 'Failed to fetch activities'}), 500

# ---------------------------------------
# Health Metrics Routes
# ---------------------------------------
@app.route('/api/health-metrics', methods=['POST'])
@login_required
def log_health_metric():
    try:
        data = request.get_json()
        metric_type = data.get('metric_type')  # e.g., 'weight', 'blood_pressure', 'heart_rate'
        value = data.get('value')
        unit = data.get('unit', '')
        notes = data.get('notes', '')
        
        if not metric_type or value is None:
            return jsonify({'error': 'Metric type and value are required'}), 400
        
        metric_id = str(uuid.uuid4())
        metric_data = {
            'metric_id': metric_id,
            'user_id': session['user_id'],
            'metric_type': metric_type,
            'value': float(value),
            'unit': unit,
            'notes': notes,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now().isoformat()
        }
        
        if dynamodb:
            health_metrics_table = get_health_metrics_table()
            health_metrics_table.put_item(Item=metric_data)
        else:
            if session['user_id'] not in local_db['health_metrics']:
                local_db['health_metrics'][session['user_id']] = []
            local_db['health_metrics'][session['user_id']].append(metric_data)
        
        logger.info(f"Health metric logged: {metric_type} for user {session['user_id']}")
        return jsonify({'message': 'Health metric logged successfully', 'metric_id': metric_id}), 201
        
    except Exception as e:
        logger.error(f"Error logging health metric: {e}")
        return jsonify({'error': 'Failed to log health metric'}), 500

@app.route('/api/health-metrics', methods=['GET'])
@login_required
def get_health_metrics():
    try:
        metric_type = request.args.get('metric_type')
        limit = int(request.args.get('limit', 10))
        
        if dynamodb:
            health_metrics_table = get_health_metrics_table()
            response = health_metrics_table.scan()
            user_metrics = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_metrics = local_db['health_metrics'].get(session['user_id'], [])
        
        # Filter by metric type if specified
        if metric_type:
            user_metrics = [m for m in user_metrics if m['metric_type'] == metric_type]
        
        # Sort by timestamp (newest first)
        user_metrics.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Apply limit
        metrics = user_metrics[:limit]
        
        return jsonify({'health_metrics': metrics}), 200
        
    except Exception as e:
        logger.error(f"Error fetching health metrics: {e}")
        return jsonify({'error': 'Failed to fetch health metrics'}), 500

# ---------------------------------------
# Wellness Goals Routes
# ---------------------------------------
@app.route('/api/goals', methods=['POST'])
@login_required
def create_goal():
    try:
        data = request.get_json()
        goal_type = data.get('goal_type')  # e.g., 'weight_loss', 'exercise_frequency'
        target_value = data.get('target_value')
        current_value = data.get('current_value', 0)
        target_date = data.get('target_date')
        description = data.get('description', '')
        
        if not goal_type or target_value is None:
            return jsonify({'error': 'Goal type and target value are required'}), 400
        
        goal_id = str(uuid.uuid4())
        goal_data = {
            'goal_id': goal_id,
            'user_id': session['user_id'],
            'goal_type': goal_type,
            'target_value': float(target_value),
            'current_value': float(current_value),
            'target_date': target_date,
            'description': description,
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        
        if dynamodb:
            goals_table = get_goals_table()
            goals_table.put_item(Item=goal_data)
        else:
            if session['user_id'] not in local_db['goals']:
                local_db['goals'][session['user_id']] = []
            local_db['goals'][session['user_id']].append(goal_data)
        
        logger.info(f"Goal created: {goal_type} for user {session['user_id']}")
        return jsonify({'message': 'Goal created successfully', 'goal_id': goal_id}), 201
        
    except Exception as e:
        logger.error(f"Error creating goal: {e}")
        return jsonify({'error': 'Failed to create goal'}), 500

@app.route('/api/goals', methods=['GET'])
@login_required
def get_goals():
    try:
        if dynamodb:
            goals_table = get_goals_table()
            response = goals_table.scan()
            user_goals = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_goals = local_db['goals'].get(session['user_id'], [])
        
        # Filter active goals
        active_goals = [g for g in user_goals if g.get('status') == 'active']
        
        return jsonify({'goals': active_goals}), 200
        
    except Exception as e:
        logger.error(f"Error fetching goals: {e}")
        return jsonify({'error': 'Failed to fetch goals'}), 500

# ---------------------------------------
# Dashboard Route
# ---------------------------------------
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    try:
        # Get recent activities
        recent_activities = []
        if dynamodb:
            activities_table = get_activities_table()
            response = activities_table.scan()
            user_activities = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_activities = local_db['activities'].get(session['user_id'], [])
        
        user_activities.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_activities = user_activities[:5]
        
        # Get recent health metrics
        recent_metrics = []
        if dynamodb:
            health_metrics_table = get_health_metrics_table()
            response = health_metrics_table.scan()
            user_metrics = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_metrics = local_db['health_metrics'].get(session['user_id'], [])
        
        user_metrics.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_metrics = user_metrics[:5]
        
        # Get active goals
        active_goals = []
        if dynamodb:
            goals_table = get_goals_table()
            response = goals_table.scan()
            user_goals = [item for item in response['Items'] if item['user_id'] == session['user_id']]
        else:
            user_goals = local_db['goals'].get(session['user_id'], [])
        
        active_goals = [g for g in user_goals if g.get('status') == 'active']
        
        # Calculate some basic stats
        total_activities = len(user_activities)
        total_calories = sum([a.get('calories_burned', 0) for a in user_activities])
        
        # This week's activities
        today = datetime.now()
        week_start = today - timedelta(days=today.weekday())
        this_week_activities = [
            a for a in user_activities 
            if datetime.fromisoformat(a['timestamp']).date() >= week_start.date()
        ]
        
        dashboard_data = {
            'user_info': {
                'name': session['name'],
                'email': session['email']
            },
            'stats': {
                'total_activities': total_activities,
                'total_calories_burned': total_calories,
                'this_week_activities': len(this_week_activities),
                'active_goals': len(active_goals)
            },
            'recent_activities': recent_activities,
            'recent_health_metrics': recent_metrics,
            'active_goals': active_goals
        }
        
        return jsonify(dashboard_data), 200
        
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {e}")
        return jsonify({'error': 'Failed to fetch dashboard data'}), 500

# ---------------------------------------
# Template Routes
# ---------------------------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')  # This should render the landing page

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')  # This renders the login form

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')
    
@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard template page"""
    return render_template('dashboard.html')

@app.route('/activities')
@login_required
def activities_page():
    return render_template('activities.html')
@app.route('/health_metrics')
@login_required
def health_metrics():
    return render_template('healt_metrics.html')

@app.route('/goals')
@login_required
def goals_page():
    return render_template('goals.html')

# ---------------------------------------
# Health Check Route
# ---------------------------------------
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'WellnessTracker API'
    }), 200

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ---------------------------------------
# Logging Configuration
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("wellness_tracker.log"),
        logging.StreamHandler()
    ]
)

if __name__ == '__main__':
    logger.info("Starting WellnessTracker API server...")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
