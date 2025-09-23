from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import csv
import io
from flask_mail import Mail, Message
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

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

# Database setup
DATABASE = 'complaints.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
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

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, name, email, role):
        self.id = id
        self.name = name
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return User(user['id'], user['name'], user['email'], user['role'])
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
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['name'], user['email'], user['role'])
            login_user(user_obj)
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
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
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO complaints (user_id, title, description, category, priority, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (current_user.id, title, description, category, priority, 'Pending'))
        
        conn.commit()
        conn.close()
        
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

if __name__ == '__main__':
    init_db()
    # Bind to 0.0.0.0 and use PORT env var for Heroku/local container support
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
