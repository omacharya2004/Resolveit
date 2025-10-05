from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import csv
import io
import re
import time
from functools import wraps
from flask_mail import Mail, Message
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import requests
import json
from dotenv import load_dotenv

def validate_password(password):
    """
    Validate password strength according to security requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password must be no more than 128 characters long"
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for at least one digit
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    # Check for at least one special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)"
    
    # Check for common weak patterns
    weak_patterns = [
        r'(.)\1{2,}',  # 3 or more consecutive identical characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        r'(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)',  # Keyboard patterns
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            return False, "Password contains common patterns that are easy to guess"
    
    # Check for common passwords
    common_passwords = [
        'password', 'password123', 'admin', 'admin123', '123456', '123456789',
        'qwerty', 'abc123', 'letmein', 'welcome', 'monkey', 'dragon',
        'master', 'hello', 'login', 'pass', '1234', '12345'
    ]
    
    if password.lower() in common_passwords:
        return False, "Password is too common and easily guessable"
    
    return True, "Password is strong"

load_dotenv()
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Performance optimizations
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year cache for static files

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/auth/google/callback')
GOOGLE_OAUTH_CONFIGURED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Flask-Mail configuration (use environment variables; falls back to disabled if missing)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587)) if os.environ.get('MAIL_PORT') else None
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true' if os.environ.get('MAIL_USE_TLS') else None
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true' if os.environ.get('MAIL_USE_SSL') else None
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME'))

mail = Mail(app)

def send_email_safely(subject: str, recipients: list[str], body: str) -> None:
    """Send an email and swallow errors so app flow is never blocked."""
    try:
        # If MAIL_SERVER is not configured, skip sending silently
        if not app.config.get('MAIL_SERVER') or not recipients:
            return
        msg = Message(subject=subject, recipients=recipients, body=body)
        # Default sender is configured above; Message will use it
        mail.send(msg)
    except Exception as e:
        # Log to console for debug; do not interrupt request
        print(f"[mail] Failed to send email: {e}")

# Database setup - Enhanced for better persistence
def get_database_path():
    """Get the appropriate database path with fallback options"""
    # Check for custom database path first
    if os.environ.get('DATABASE_PATH'):
        return os.environ.get('DATABASE_PATH')
    
    # For production environments, use a persistent location
    if os.environ.get('VERCEL'):
        # On Vercel, use a more persistent location
        persistent_path = '/var/task/complaints.db'
        if os.path.exists('/var/task') and os.access('/var/task', os.W_OK):
            return persistent_path
        # Fallback to tmp but with backup mechanism
        return '/tmp/complaints.db'
    
    # For local development and other environments
    return 'complaints.db'

DATABASE = get_database_path()

def backup_database():
    """Create a backup of the database"""
    try:
        if os.path.exists(DATABASE):
            backup_path = f"{DATABASE}.backup"
            import shutil
            shutil.copy2(DATABASE, backup_path)
            print(f"[backup] Database backed up to {backup_path}")
            return True
    except Exception as e:
        print(f"[backup] Failed to backup database: {e}")
    return False

def restore_database():
    """Restore database from backup if main database is missing or empty"""
    try:
        backup_path = f"{DATABASE}.backup"
        if os.path.exists(backup_path) and (not os.path.exists(DATABASE) or os.path.getsize(DATABASE) == 0):
            import shutil
            shutil.copy2(backup_path, DATABASE)
            print(f"[restore] Database restored from {backup_path}")
            return True
    except Exception as e:
        print(f"[restore] Failed to restore database: {e}")
    return False

def init_db():
    """Initialize the database with required tables and ensure persistence"""
    try:
        # Try to restore from backup if needed (only if database doesn't exist)
        if not os.path.exists(DATABASE):
            restore_database()
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Enable WAL mode for better performance
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.execute('PRAGMA cache_size=10000')
        cursor.execute('PRAGMA temp_store=MEMORY')
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                role TEXT DEFAULT 'user',
                address TEXT DEFAULT '',
                google_id TEXT UNIQUE,
                profile_picture TEXT,
                auth_provider TEXT DEFAULT 'local'
            )
        ''')
        
        # Add new columns to existing users table if they don't exist
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN address TEXT DEFAULT ""')
        except:
            pass
        
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN google_id TEXT UNIQUE')
        except:
            pass
            
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN profile_picture TEXT')
        except:
            pass
            
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT "local"')
        except:
            pass  # Column already exists
        
        # Create complaints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                priority TEXT DEFAULT 'Medium',
                status TEXT DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                admin_reply TEXT,
                replied_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
    
        # Add new columns to existing table if they don't exist
        try:
            cursor.execute('ALTER TABLE complaints ADD COLUMN category TEXT DEFAULT "General"')
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute('ALTER TABLE complaints ADD COLUMN priority TEXT DEFAULT "Medium"')
        except sqlite3.OperationalError:
            pass  # Column already exists
    
        # Residential fields for complaints (idempotent migrations)
        for column_def in [
            'society TEXT DEFAULT ""',
            'block TEXT DEFAULT ""',
            'wing TEXT DEFAULT ""',
            'floor TEXT DEFAULT ""',
            'flat_no TEXT DEFAULT ""',
            'address TEXT DEFAULT ""',
            'landmark TEXT DEFAULT ""',
            'contact_phone TEXT DEFAULT ""',
            'preferred_visit_time TEXT DEFAULT ""'
        ]:
            try:
                cursor.execute(f'ALTER TABLE complaints ADD COLUMN {column_def}')
            except sqlite3.OperationalError:
                pass

        # Add admin_reply and replied_at if they don't exist (for reply feature)
        try:
            cursor.execute('ALTER TABLE complaints ADD COLUMN admin_reply TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE complaints ADD COLUMN replied_at TIMESTAMP')
        except sqlite3.OperationalError:
            pass
        
        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            admin_password = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            ''', ('Admin User', 'om_admin@gmail.com', admin_password, 'admin'))
    
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Continue anyway - the app can still work with basic functionality

# Ensure DB schema is initialized on import (covers `flask run` and WSGI servers)
try:
    init_db()
except Exception as e:
    print(f"[init_db] Schema initialization failed: {e}")

def validate_database_integrity():
    """Validate database integrity and check for data loss"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='complaints'")
        if not cursor.fetchone():
            print("[integrity] Complaints table missing!")
            return False
            
        # Check if there are any complaints
        cursor.execute("SELECT COUNT(*) FROM complaints")
        complaint_count = cursor.fetchone()[0]
        print(f"[integrity] Found {complaint_count} complaints in database")
        
        # Check for recent complaints (last 24 hours)
        cursor.execute("SELECT COUNT(*) FROM complaints WHERE created_at > datetime('now', '-1 day')")
        recent_count = cursor.fetchone()[0]
        print(f"[integrity] Found {recent_count} recent complaints")
        
        conn.close()
        return True
    except Exception as e:
        print(f"[integrity] Database integrity check failed: {e}")
        return False

def get_db_connection():
    """Get database connection with integrity check"""
    # Perform integrity check before returning connection
    if not validate_database_integrity():
        print("[db] Database integrity issues detected, attempting restore...")
        restore_database()
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, name, email, role, google_id=None, profile_picture=None, auth_provider='local'):
        self.id = id
        self.name = name
        self.email = email
        self.role = role
        self.google_id = google_id
        self.profile_picture = profile_picture
        self.auth_provider = auth_provider

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        keys = user.keys() if hasattr(user, 'keys') else []
        google_id = user['google_id'] if 'google_id' in keys else None
        profile_picture = user['profile_picture'] if 'profile_picture' in keys else None
        auth_provider = user['auth_provider'] if 'auth_provider' in keys else 'local'
        return User(
            user['id'],
            user['name'],
            user['email'],
            user['role'],
            google_id,
            profile_picture,
            auth_provider
        )
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Validate password strength
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if email already exists
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            flash('Email already registered. Please use a different email.', 'error')
            conn.close()
            return render_template('register.html')
        
        # Hash password and insert user
        hashed_password = generate_password_hash(password)
        conn.execute('''
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        ''', (name, email, hashed_password, 'user'))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', google_oauth_configured=GOOGLE_OAUTH_CONFIGURED)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to main login page with options
    return render_template('login.html', google_oauth_configured=GOOGLE_OAUTH_CONFIGURED)

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'user')).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['name'], user['email'], user['role'])
            login_user(user_obj)
            flash('Welcome back!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password. Please make sure you are using a user account.', 'error')
    
    return render_template('user_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['name'], user['email'], user['role'])
            login_user(user_obj)
            flash('Welcome back, Administrator!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password. Please make sure you are using an admin account.', 'error')
    
    return render_template('admin_login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Google OAuth Routes
@app.route('/auth/google')
def google_auth():
    """Initiate Google OAuth flow"""
    if not GOOGLE_CLIENT_ID:
        flash('Google authentication is not configured. Please contact the administrator.', 'error')
        return redirect(url_for('login'))
    
    # Store the next page in session for redirect after login
    next_page = request.args.get('next')
    if next_page:
        session['next'] = next_page
    
    # Google OAuth URL
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"scope=openid%20email%20profile&"
        f"response_type=code&"
        f"access_type=offline"
    )
    
    return redirect(google_auth_url)

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash('Google authentication was cancelled or failed.', 'error')
        return redirect(url_for('login'))
    
    if not code:
        flash('Google authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Exchange code for access token
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        token_json = token_response.json()
        access_token = token_json['access_token']
        
        # Get user info from Google
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get(user_info_url, headers=headers)
        user_response.raise_for_status()
        user_info = user_response.json()
        
        # Extract user information
        google_id = user_info['id']
        email = user_info['email']
        name = user_info['name']
        profile_picture = user_info.get('picture')
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute(
            'SELECT * FROM users WHERE email = ? OR google_id = ?', 
            (email, google_id)
        ).fetchone()
        
        if existing_user:
            # Update existing user with Google info if needed
            if not existing_user['google_id']:
                conn.execute(
                    'UPDATE users SET google_id = ?, profile_picture = ?, auth_provider = ? WHERE id = ?',
                    (google_id, profile_picture, 'google', existing_user['id'])
                )
                conn.commit()
            
            user = User(
                existing_user['id'],
                existing_user['name'],
                existing_user['email'],
                existing_user['role'],
                google_id,
                profile_picture,
                'google'
            )
        else:
            # Create new user
            cursor = conn.execute(
                'INSERT INTO users (name, email, google_id, profile_picture, auth_provider) VALUES (?, ?, ?, ?, ?)',
                (name, email, google_id, profile_picture, 'google')
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            user = User(
                user_id,
                name,
                email,
                'user',  # Default role
                google_id,
                profile_picture,
                'google'
            )
        
        conn.close()
        
        # Log the user in
        login_user(user)
        flash(f'Welcome back, {name}!', 'success')
        
        # Redirect to next page or dashboard
        next_page = session.pop('next', None)
        if next_page:
            return redirect(next_page)
        
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
            
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    complaints = conn.execute('''
        SELECT * FROM complaints 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', complaints=complaints)

@app.route('/submit_complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form.get('category', 'General')
        priority = request.form.get('priority', 'Medium')
        
        # Residential context fields (optional)
        society = request.form.get('society', '').strip()
        block = request.form.get('block', '').strip()
        wing = request.form.get('wing', '').strip()
        floor = request.form.get('floor', '').strip()
        flat_no = request.form.get('flat_no', '').strip()
        address = request.form.get('address', '').strip()
        landmark = request.form.get('landmark', '').strip()
        contact_phone = request.form.get('contact_phone', '').strip()
        preferred_visit_time = request.form.get('preferred_visit_time', '').strip()

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO complaints (
                user_id, title, description, category, priority, status,
                society, block, wing, floor, flat_no, address, landmark,
                contact_phone, preferred_visit_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            current_user.id, title, description, category, priority, 'Pending',
            society, block, wing, floor, flat_no, address, landmark,
            contact_phone, preferred_visit_time
        ))
        
        conn.commit()
        conn.close()
        
        # Create backup after successful complaint submission
        backup_database()
        
        flash('Complaint submitted successfully!', 'success')

        # Send confirmation email to the user (non-blocking)
        try:
            subject = 'ResolveIt: Complaint submitted successfully'
            body = (
                f"Hello {current_user.name},\n\n"
                f"We have received your complaint titled: '{title}'.\n"
                f"Current status: Pending.\n\n"
                f"We will keep you updated on any changes.\n\n"
                f"Regards,\nResolveIt"
            )
            send_email_safely(subject, [current_user.email], body)
        except Exception as e:
            print(f"[mail] submit_complaint notification error: {e}")
        return redirect(url_for('user_dashboard'))
    
    return render_template('submit_complaint.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Get current user's password from database
        conn = get_db_connection()
        user = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()
        
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'error')
            conn.close()
            return render_template('change_password.html')
        
        # Check if new password matches confirmation
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            conn.close()
            return render_template('change_password.html')
        
        # Validate new password strength
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message, 'error')
            conn.close()
            return render_template('change_password.html')
        
        # Update password
        hashed_new_password = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_new_password, current_user.id))
        conn.commit()
        conn.close()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('change_password.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    complaints = conn.execute('''
        SELECT c.*, u.name as user_name, u.email as user_email
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin.html', complaints=complaints)

@app.route('/update_status/<int:complaint_id>', methods=['POST'])
@login_required
def update_status(complaint_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    new_status = request.form['status']
    
    conn = get_db_connection()
    # Fetch complaint details and user email for notification
    comp = conn.execute('''
        SELECT c.title, c.created_at, u.email AS user_email, u.name AS user_name
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    ''', (complaint_id,)).fetchone()
    
    # Enforce 7-day minimum before allowing Resolved
    if new_status == 'Resolved' and comp and comp['created_at']:
        try:
            created_dt = datetime.fromisoformat(str(comp['created_at']))
        except Exception:
            # Fallback parse for sqlite timestamp "YYYY-MM-DD HH:MM:SS"
            created_dt = datetime.strptime(str(comp['created_at'])[:19], '%Y-%m-%d %H:%M:%S')
        if datetime.now() < created_dt + timedelta(days=7):
            conn.close()
            flash('Complaints can only be marked Resolved after 7 days from submission.', 'error')
            return redirect(url_for('admin_dashboard'))

    conn.execute('''
        UPDATE complaints 
        SET status = ? 
        WHERE id = ?
    ''', (new_status, complaint_id))
    conn.commit()
    conn.close()
    
    # Create backup after successful status update
    backup_database()
    
    flash('Complaint status updated successfully!', 'success')

    # Send status update email to the user (non-blocking)
    try:
        if comp and comp['user_email']:
            subject = 'ResolveIt: Complaint status updated'
            body = (
                f"Hello {comp['user_name']},\n\n"
                f"The status of your complaint has been updated.\n"
                f"Title: '{comp['title']}'\n"
                f"New Status: {new_status}\n\n"
                f"You can log in to view more details.\n\n"
                f"Regards,\nResolveIt"
            )
            send_email_safely(subject, [comp['user_email']], body)
    except Exception as e:
        print(f"[mail] update_status notification error: {e}")
    return redirect(url_for('admin_dashboard'))

@app.route('/reply/<int:complaint_id>', methods=['POST'])
@login_required
def reply_to_complaint(complaint_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    reply_text = request.form.get('reply', '').strip()
    if not reply_text:
        flash('Reply cannot be empty.', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    # Fetch for notification and to validate complaint exists
    comp = conn.execute('''
        SELECT c.id, c.status, c.title, u.email AS user_email, u.name AS user_name
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    ''', (complaint_id,)).fetchone()
    if not comp:
        conn.close()
        flash('Complaint not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Save reply and timestamp; optionally move to In Progress if still Pending
    new_status = comp['status'] if comp['status'] != 'Pending' else 'In Progress'
    conn.execute('''
        UPDATE complaints
        SET admin_reply = ?, replied_at = CURRENT_TIMESTAMP, status = ?
        WHERE id = ?
    ''', (reply_text, new_status, complaint_id))
    conn.commit()
    conn.close()
    
    # Create backup after successful reply
    backup_database()

    flash('Reply sent to user successfully!', 'success')

    # Send reply email to the user (non-blocking)
    try:
        if comp and comp['user_email']:
            subject = 'ResolveIt: Update on your complaint'
            body = (
                f"Hello {comp['user_name']},\n\n"
                f"An administrator has replied to your complaint.\n"
                f"Title: '{comp['title']}'\n\n"
                f"Reply:\n{reply_text}\n\n"
                f"You can log in to view more details.\n\n"
                f"Regards,\nResolveIt"
            )
            send_email_safely(subject, [comp['user_email']], body)
    except Exception as e:
        print(f"[mail] reply_to_complaint notification error: {e}")
    return redirect(url_for('admin_dashboard'))

@app.route('/download_csv')
@login_required
def download_csv():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    complaints = conn.execute('''
        SELECT c.title, c.description, c.category, c.priority, c.status, c.created_at, u.name as user_name, u.email as user_email
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['User', 'Title', 'Category', 'Priority', 'Status', 'Date'])
    
    # Write data
    for complaint in complaints:
        writer.writerow([
            complaint['user_name'],
            complaint['title'],
            complaint['category'],
            complaint['priority'],
            complaint['status'],
            complaint['created_at']
        ])
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=complaints_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route('/download_pdf')
@login_required
def download_pdf():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    complaints = conn.execute('''
        SELECT c.title, c.description, c.category, c.priority, c.status, c.created_at, u.name as user_name, u.email as user_email
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=1*inch)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=1,  # Center alignment
        textColor=colors.darkblue
    )
    
    # Content
    story = []
    
    # Title
    title = Paragraph("Complaints Management System - Report", title_style)
    story.append(title)
    story.append(Spacer(1, 20))
    
    # Report info
    report_info = Paragraph(f"<b>Generated on:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    story.append(report_info)
    story.append(Paragraph(f"<b>Total Complaints:</b> {len(complaints)}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Table data
    table_data = [['User', 'Title', 'Category', 'Priority', 'Status', 'Date']]
    
    for complaint in complaints:
        table_data.append([
            complaint['user_name'],
            complaint['title'][:30] + '...' if len(complaint['title']) > 30 else complaint['title'],
            complaint['category'],
            complaint['priority'],
            complaint['status'],
            complaint['created_at'][:10]  # Date only
        ])
    
    # Create table
    table = Table(table_data, colWidths=[1.2*inch, 2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    story.append(table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    # Create response
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=complaints_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    
    return response
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin/database-status')
@login_required
def database_status():
    """Admin route to check database status and health"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    try:
        conn = get_db_connection()
        
        # Get database statistics
        stats = {}
        
        # Total complaints
        cursor = conn.execute("SELECT COUNT(*) FROM complaints")
        stats['total_complaints'] = cursor.fetchone()[0]
        
        # Complaints by status
        cursor = conn.execute("SELECT status, COUNT(*) FROM complaints GROUP BY status")
        stats['by_status'] = dict(cursor.fetchall())
        
        # Recent complaints (last 7 days)
        cursor = conn.execute("SELECT COUNT(*) FROM complaints WHERE created_at > datetime('now', '-7 days')")
        stats['recent_complaints'] = cursor.fetchone()[0]
        
        # Database file info
        import os
        if os.path.exists(DATABASE):
            stats['database_size'] = os.path.getsize(DATABASE)
            stats['database_path'] = DATABASE
        else:
            stats['database_size'] = 0
            stats['database_path'] = "Database file not found!"
        
        # Check backup
        backup_path = f"{DATABASE}.backup"
        if os.path.exists(backup_path):
            stats['backup_size'] = os.path.getsize(backup_path)
            stats['backup_exists'] = True
        else:
            stats['backup_size'] = 0
            stats['backup_exists'] = False
        
        conn.close()
        
        return render_template('database_status.html', stats=stats)
        
    except Exception as e:
        flash(f'Error checking database status: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/backup-database')
@login_required
def manual_backup():
    """Admin route to manually trigger database backup"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('user_dashboard'))
    
    if backup_database():
        flash('Database backup created successfully!', 'success')
    else:
        flash('Failed to create database backup.', 'error')
    
    return redirect(url_for('database_status'))

@app.route('/complaint/<int:complaint_id>')
@login_required
def view_complaint_details(complaint_id):
    """View detailed information about a specific complaint"""
    conn = get_db_connection()
    
    # Get complaint details with user information
    complaint = conn.execute('''
        SELECT c.*, u.name as user_name, u.email as user_email
        FROM complaints c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    ''', (complaint_id,)).fetchone()
    
    conn.close()
    
    if not complaint:
        flash('Complaint not found.', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Check if user has permission to view this complaint
    if current_user.role != 'admin' and complaint['user_id'] != current_user.id:
        flash('Access denied. You can only view your own complaints.', 'error')
        return redirect(url_for('user_dashboard'))
    
    return render_template('complaint_details.html', complaint=complaint)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html')

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile information"""
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        
        # Validate required fields
        if not name or not email:
            flash('Name and email are required.', 'error')
            return redirect(url_for('profile'))
        
        # Validate email format
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('profile'))
        
        # Check if email is already taken by another user
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            (email, current_user.id)
        ).fetchone()
        
        if existing_user:
            flash('This email is already registered to another account.', 'error')
            conn.close()
            return redirect(url_for('profile'))
        
        # Update user profile
        conn.execute('''
            UPDATE users 
            SET name = ?, email = ?, address = ?
            WHERE id = ?
        ''', (name, email, address, current_user.id))
        
        conn.commit()
        conn.close()
        
        # Update current user object
        current_user.name = name
        current_user.email = email
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
        
    except Exception as e:
        flash('An error occurred while updating your profile.', 'error')
        return redirect(url_for('profile'))

@app.route('/health')
def health_check():
    """Health check endpoint for Render and monitoring"""
    try:
        # Quick database connectivity check
        conn = get_db_connection()
        conn.execute('SELECT 1')
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 500

@app.route('/ping')
def ping():
    """Simple ping endpoint for load balancers"""
    return 'pong', 200

@app.route('/loading')
def loading():
    """Loading page for better user experience"""
    return render_template('loading.html')

# Performance optimization decorator
def cache_response(timeout=300):
    """Cache response for specified time in seconds"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory cache (for production, use Redis or similar)
            cache_key = f"{request.endpoint}_{hash(str(request.args))}"
            if hasattr(app, 'cache') and cache_key in app.cache:
                cached_data, timestamp = app.cache[cache_key]
                if time.time() - timestamp < timeout:
                    return cached_data
            
            response = f(*args, **kwargs)
            
            if not hasattr(app, 'cache'):
                app.cache = {}
            app.cache[cache_key] = (response, time.time())
            
            return response
        return decorated_function
    return decorator

@app.after_request
def after_request(response):
    """Add caching headers for better performance"""
    # Cache static files for 1 year
    if request.endpoint == 'static':
        response.headers['Cache-Control'] = 'public, max-age=31536000'
    # Cache HTML pages for 5 minutes
    elif request.endpoint in ['index', 'about']:
        response.headers['Cache-Control'] = 'public, max-age=300'
    # No cache for dynamic content
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

if __name__ == '__main__':
    # Optimize for production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Initialize database only if needed
    if not os.path.exists(DATABASE):
        init_db()
    
    # Bind to 0.0.0.0 and use PORT env var for Heroku/local container support
    port = int(os.environ.get('PORT', 5000))
    
    # Production optimizations
    if not debug_mode:
        # Use threaded mode for better performance
        app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
    else:
        app.run(debug=True, host='0.0.0.0', port=port)
