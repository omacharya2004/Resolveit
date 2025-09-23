# Complaint Management System

A Flask web application for managing complaints with user authentication and admin dashboard functionality.

## Features

- **User Authentication**: Secure registration and login system with password hashing
- **User Dashboard**: Users can submit complaints and view their complaint status
- **Admin Dashboard**: Admins can view all complaints and update their status
- **Status Management**: Three complaint statuses - Pending, In Progress, Resolved
- **Responsive Design**: Clean Bootstrap-based UI that works on all devices
- **SQLite Database**: Lightweight database for storing user and complaint data

## User Roles

### Users
- Register for a new account
- Login to access their dashboard
- Submit new complaints with title and description
- View all their submitted complaints and their current status

### Admin
- Login with admin credentials
- View all complaints from all users
- Update complaint status (Pending → In Progress → Resolved)
- View complaint statistics and user information

## Project Structure

```
Complaint Management System/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User dashboard
│   ├── submit_complaint.html # Complaint submission form
│   └── admin.html        # Admin dashboard
├── static/               # Static files (CSS, JS, images)
└── complaints.db         # SQLite database (created automatically)
```

## Installation & Setup

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Clone or Download
Download this project to your local machine and navigate to the project directory.

### Step 2: Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```

The application will start on `http://localhost:5000` or `http://127.0.0.1:5000`

## Deploy to Heroku

1) Prereqs
- Install Heroku CLI and log in: `heroku login`
- Ensure this repo is pushed to GitHub

2) One-time app creation
```bash
heroku create resolveit-cms
```

3) Set environment variables (optional for email)
```bash
heroku config:set MAIL_SERVER=smtp.example.com MAIL_PORT=587 MAIL_USE_TLS=true MAIL_USERNAME=you@example.com MAIL_PASSWORD=secret MAIL_DEFAULT_SENDER=you@example.com
```

4) Deploy
```bash
git push heroku HEAD:main   # or HEAD:master depending on your default branch
```

Heroku will install from `requirements.txt` and run using `Procfile`:
```
web: gunicorn app:app
```

5) Open the app
```bash
heroku open
```

Notes
- The app binds to `0.0.0.0` and reads `PORT` automatically on Heroku.
- Database here is SQLite (file-based). For multi-dyno or persistent cloud DB, use Postgres (Heroku Postgres addon) and migrate code accordingly.

## Default Admin Account

The system creates a default admin account when first run:
- **Email**: om_admin@gmail.com
- **Password**: admin123

**Important**: Change these credentials in production!

## Usage

### For Users:
1. Visit the application URL
2. Click "Register" to create a new account
3. Login with your credentials
4. Submit complaints using the "Submit New Complaint" button
5. View your complaint status on the dashboard

### For Admins:
1. Login with admin credentials (admin@example.com / admin123)
2. Access the admin dashboard to view all complaints
3. Update complaint status using the dropdown in each complaint card
4. Monitor complaint statistics

## Database Schema

### Users Table
- `id`: Primary key
- `name`: User's full name
- `email`: User's email (unique)
- `password`: Hashed password
- `role`: User role ('user' or 'admin')

### Complaints Table
- `id`: Primary key
- `user_id`: Foreign key to users table
- `title`: Complaint title
- `description`: Detailed complaint description
- `status`: Current status ('Pending', 'In Progress', 'Resolved')
- `created_at`: Timestamp when complaint was created

## Security Features

- Password hashing using Werkzeug
- Session management with Flask-Login
- Role-based access control
- SQL injection protection with parameterized queries

## Technologies Used

- **Backend**: Flask (Python web framework)
- **Database**: SQLite (lightweight, file-based database)
- **Authentication**: Flask-Login
- **Password Hashing**: Werkzeug
- **Frontend**: HTML5, Bootstrap 5, Font Awesome icons
- **Responsive Design**: Bootstrap CSS framework

## Development Notes

- The application runs in debug mode by default
- Database is automatically created and initialized on first run
- Default admin user is created automatically if no admin exists
- All templates use Bootstrap for consistent styling

## Production Deployment

For production deployment:
1. Change the secret key in `app.py`
2. Set `debug=False` in the Flask app configuration
3. Use a production WSGI server like Gunicorn
4. Set up a proper database (PostgreSQL, MySQL) instead of SQLite
5. Configure environment variables for sensitive data
6. Set up SSL/HTTPS

## License

This project is open source and available under the MIT License.
