from flask import Flask, request, redirect, url_for, render_template_string, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import threading
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "supersecretkey")
DB_FILE = "smartboard.db"

# SMTP Configuration - Set these environment variables
SMTP_HOST = os.environ.get("SMTP_HOST")  # e.g., "smtp.gmail.com"
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))  # Gmail: 587, Outlook: 587
SMTP_USER = os.environ.get("SMTP_USER")  # Your email address
SMTP_PASS = os.environ.get("SMTP_PASS")  # Your email password or app password
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)  # From email address
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() == "true"  # Use TLS

# Admin notification settings
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")  # Admin email for notifications

# Time slot options
TIME_SLOTS = [
    "08:30", "09:30", "10:30", "11:30", "12:30", 
    "13:30", "14:30", "15:30", "16:30"
]

# ---------- UTILITIES ----------
def calculate_end_time(start_time):
    """Calculate end time (1 hour after start time)"""
    hour, minute = map(int, start_time.split(':'))
    end_hour = hour + 1
    # Handle overflow (though unlikely with our time slots)
    if end_hour >= 24:
        end_hour = 23
        minute = 59
    return f"{end_hour:02d}:{minute:02d}"

# ---------- DATABASE SETUP ----------
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    db = get_db()
    # Users table
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','faculty')),
        email_notifications INTEGER DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )""")
    
    # Password reset tokens table
    db.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")
    
    # Classrooms table (capacity column removed)
    db.execute("""
    CREATE TABLE IF NOT EXISTS classrooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        equipment TEXT
    )""")
    
    # Bookings table
    db.execute("""
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        booking_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        purpose TEXT,
        status TEXT DEFAULT 'confirmed' CHECK(status IN ('confirmed','cancelled')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")
    
    # Email notifications log
    db.execute("""
    CREATE TABLE IF NOT EXISTS email_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','sent','failed')),
        attempts INTEGER DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        sent_at TEXT
    )""")
    
    # Check if capacity column exists and remove it
    try:
        db.execute("ALTER TABLE classrooms DROP COLUMN capacity")
    except sqlite3.OperationalError:
        pass  # Column might not exist or already removed
    
    # Seed admin if none exists
    c = db.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
    if c == 0:
        admin_email = ADMIN_EMAIL or "admin@example.com"
        db.execute(
            "INSERT INTO users (username,email,password_hash,full_name,role) VALUES (?,?,?,?,?)",
            ("admin", admin_email, generate_password_hash("admin123"), "Administrator", "admin")
        )
    
    # Seed classrooms
    c = db.execute("SELECT COUNT(*) AS c FROM classrooms").fetchone()["c"]
    if c == 0:
        classrooms = [
            ("Smartboard Room 1", "Interactive Whiteboard, Projector, Audio System"),
            ("Smartboard Room 2", "Interactive Whiteboard, Projector, Audio System, Document Camera"),
            ("Conference Room A", "Smart TV, Video Conferencing Setup"),
        ]
        db.executemany("INSERT INTO classrooms (name, equipment) VALUES (?,?)", classrooms)
    
    db.commit()
    db.close()

# ---------- PASSWORD RESET FUNCTIONS ----------
def generate_reset_token():
    """Generate a secure password reset token"""
    return str(uuid.uuid4())

def create_password_reset_token(user_id):
    """Create a password reset token for a user"""
    db = get_db()
    token = generate_reset_token()
    expires_at = (datetime.now() + timedelta(hours=1)).isoformat()  # Token expires in 1 hour
    
    # Clean up old tokens for this user
    db.execute("DELETE FROM password_reset_tokens WHERE user_id = ? OR expires_at < datetime('now')", (user_id,))
    
    # Create new token
    db.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?,?,?)",
        (user_id, token, expires_at)
    )
    db.commit()
    db.close()
    return token

def verify_reset_token(token):
    """Verify a password reset token and return user info if valid"""
    db = get_db()
    result = db.execute("""
        SELECT prt.user_id, prt.expires_at, u.* 
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.token = ? AND prt.used = 0 AND prt.expires_at > datetime('now')
    """, (token,)).fetchone()
    db.close()
    return result

def mark_token_used(token):
    """Mark a reset token as used"""
    db = get_db()
    db.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
    db.commit()
    db.close()

def send_password_reset_link(user, token):
    """Send password reset email with link"""
    reset_url = f"{request.url_root}reset-password/{token}"
    subject = "Password Reset - Smartboard System"
    body = f"""Hello {user['full_name']},

You have requested a password reset for your Smartboard Booking System account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour for security reasons.

If you didn't request this reset, please ignore this email and your password will remain unchanged.

Best regards,
Smartboard Booking System
"""
    
    if user['email']:
        queue_email(user['email'], subject, body)
        send_email_async(user['email'], subject, body)
        return True
    return False

# ---------- EMAIL HELPER FUNCTIONS ----------
def queue_email(recipient_email, subject, body):
    """Queue an email for sending"""
    db = get_db()
    db.execute(
        "INSERT INTO email_notifications (recipient_email, subject, body) VALUES (?,?,?)",
        (recipient_email, subject, body)
    )
    db.commit()
    db.close()

def send_email_sync(to_address, subject, body):
    """Synchronously send email"""
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        app.logger.warning("SMTP not configured properly")
        return False
    
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_address
        msg.set_content(body)
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            if SMTP_TLS:
                server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        app.logger.info(f"Email sent successfully to {to_address}")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {str(e)}")
        return False

def send_email_async(to_address, subject, body):
    """Send email asynchronously"""
    def send():
        success = send_email_sync(to_address, subject, body)
        # Update email notification status in database
        db = get_db()
        status = 'sent' if success else 'failed'
        sent_at = datetime.now().isoformat() if success else None
        db.execute(
            "UPDATE email_notifications SET status=?, sent_at=?, attempts=attempts+1 WHERE recipient_email=? AND subject=? ORDER BY created_at DESC LIMIT 1",
            (status, sent_at, to_address, subject)
        )
        db.commit()
        db.close()
    
    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()

def send_booking_confirmation(user, booking_details):
    """Send booking confirmation email"""
    subject = f"Booking Confirmed - {booking_details['classroom']}"
    body = f"""Hello {user['full_name']},

Your smartboard booking has been confirmed!

Details:
- Classroom: {booking_details['classroom']}
- Date: {booking_details['booking_date']}
- Time: {booking_details['start_time']} - {booking_details['end_time']} (1 hour slot)
- Purpose: {booking_details['purpose']}

Please arrive 5 minutes early to set up your equipment.

If you need to cancel, please do so through the system or contact the admin.

Best regards,
Smartboard Booking System
"""
    
    email_notifications = user.get('email_notifications') if hasattr(user, 'get') else (user['email_notifications'] if 'email_notifications' in user.keys() else 1)
    if user['email'] and email_notifications:
        queue_email(user['email'], subject, body)
        send_email_async(user['email'], subject, body)

def send_booking_cancelled(user, booking_details, cancelled_by=None):
    """Send booking cancellation email"""
    cancelled_by_text = f" by {cancelled_by}" if cancelled_by else ""
    subject = f"Booking Cancelled - {booking_details['classroom']}"
    body = f"""Hello {user['full_name']},

Your smartboard booking has been cancelled{cancelled_by_text}.

Cancelled Booking Details:
- Classroom: {booking_details['classroom']}
- Date: {booking_details['booking_date']}
- Time: {booking_details['start_time']} - {booking_details['end_time']} (1 hour slot)
- Purpose: {booking_details['purpose']}

You can make a new booking through the system if needed.

Best regards,
Smartboard Booking System
"""
    
    email_notifications = user.get('email_notifications') if hasattr(user, 'get') else (user['email_notifications'] if 'email_notifications' in user.keys() else 1)
    if user['email'] and email_notifications:
        queue_email(user['email'], subject, body)
        send_email_async(user['email'], subject, body)

def send_admin_notification(subject, body):
    """Send notification to admin"""
    if ADMIN_EMAIL:
        queue_email(ADMIN_EMAIL, subject, body)
        send_email_async(ADMIN_EMAIL, subject, body)

def send_login_notification(user):
    """Send login notification"""
    email_notifications = user.get('email_notifications') if hasattr(user, 'get') else (user['email_notifications'] if 'email_notifications' in user.keys() else 1)
    
    if user['role'] == 'faculty' and user['email'] and email_notifications:
        subject = "Login Alert - Smartboard System"
        body = f"""Hello {user['full_name']},

You have successfully logged into the Smartboard Booking System.

Login Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {request.environ.get('REMOTE_ADDR', 'Unknown')}

If this wasn't you, please contact the administrator immediately.

Best regards,
Smartboard Booking System
"""
        queue_email(user['email'], subject, body)
        send_email_async(user['email'], subject, body)

def send_password_reset(user, temp_password):
    """Send password reset email"""
    subject = "Password Reset - Smartboard System"
    body = f"""Hello {user['full_name']},

Your password has been reset by an administrator.

Temporary Password: {temp_password}

Please log in using this temporary password and change it immediately for security.

Login URL: {request.url_root}login

Best regards,
Smartboard Booking System
"""
    
    if user['email']:
        queue_email(user['email'], subject, body)
        send_email_async(user['email'], subject, body)
        return True
    return False

def send_daily_bookings_summary():
    """Send daily bookings summary to admin (can be called by a cron job)"""
    db = get_db()
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    
    bookings = db.execute("""
        SELECT b.booking_date, b.start_time, b.end_time, b.purpose,
               c.name as classroom, u.full_name as booked_by, u.email
        FROM bookings b
        JOIN classrooms c ON b.classroom_id = c.id
        JOIN users u ON b.user_id = u.id
        WHERE b.booking_date = ? AND b.status = 'confirmed'
        ORDER BY b.start_time
    """, (tomorrow,)).fetchall()
    
    db.close()
    
    if bookings and ADMIN_EMAIL:
        subject = f"Daily Bookings Summary - {tomorrow}"
        body = f"Bookings scheduled for {tomorrow}:\n\n"
        
        for booking in bookings:
            body += f"• {booking['start_time']}-{booking['end_time']} | {booking['classroom']} | {booking['booked_by']} | {booking['purpose']}\n"
        
        body += f"\nTotal bookings: {len(bookings)}\n\nSmartboard Booking System"
        
        queue_email(ADMIN_EMAIL, subject, body)
        send_email_async(ADMIN_EMAIL, subject, body)

# ---------- AUTH HELPERS ----------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    db.close()
    return u

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if current_user() is None:
            flash("Please log in first", "error")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or u["role"] != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper

# ---------- UTILITIES ----------
def times_overlap(a_start, a_end, b_start, b_end):
    def to_min(t):
        h, m = map(int, t.split(":"))
        return h * 60 + m
    s1, e1, s2, e2 = to_min(a_start), to_min(a_end), to_min(b_start), to_min(b_end)
    return max(s1, s2) < min(e1, e2)

def booking_conflict(db, classroom_id, booking_date, start_time, end_time):
    rows = db.execute(
        "SELECT start_time, end_time FROM bookings WHERE classroom_id = ? AND booking_date = ? AND status = 'confirmed'",
        (classroom_id, booking_date)
    ).fetchall()
    for r in rows:
        if times_overlap(start_time, end_time, r["start_time"], r["end_time"]):
            return True
    return False

def generate_temp_password(n=12):
    return secrets.token_urlsafe(n)[:n]

# ---------- STYLES & BASE ----------
base_style = """
<style>
body { font-family: Arial, sans-serif; background: #f5f7fa; margin: 0; padding: 0; }
.container { width: 90%; max-width: 1100px; margin: 24px auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
h1,h2 { color: #333; }
input, select, button, textarea { padding: 8px; margin: 6px 0; border-radius: 6px; border: 1px solid #ccc; }
button { background: #007bff; color: white; cursor: pointer; }
button:hover { opacity: 0.95; }
.btn-success { background: #28a745; }
.btn-warning { background: #ffc107; color: #212529; }
.btn-danger { background: #dc3545; }
.btn-secondary { background: #6c757d; }
.table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.table th, .table td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; }
.flash { padding: 10px; margin-bottom: 12px; border-radius: 6px; }
.flash.error { background: #f8d7da; color: #721c24; }
.flash.success { background: #d4edda; color: #155724; }
.flash.info { background: #d1ecf1; color: #0c5460; }
.small-muted { color: #6c757d; font-size: 0.9rem; }
.nav { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
.nav a { margin-left:8px; color:#007bff; text-decoration:none; }
.form-group { margin-bottom: 15px; }
.form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
.status-confirmed { color: #28a745; }
.status-cancelled { color: #dc3545; }
.booking-note { background: #e9ecef; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 0.9rem; }
.forgot-password-link { display: inline-block; margin-top: 10px; color: #007bff; text-decoration: none; font-size: 0.9rem; }
.forgot-password-link:hover { text-decoration: underline; }
.auth-links { text-align: center; margin-top: 15px; }
.auth-links a { color: #007bff; text-decoration: none; margin: 0 10px; }
.auth-links a:hover { text-decoration: underline; }
</style>
"""

# ---------- ROUTES ----------
@app.route("/")
@login_required
def index():
    db = get_db()
    bookings = db.execute("""
        SELECT b.id, c.name as classroom, u.full_name as booked_by,
               b.booking_date, b.start_time, b.end_time, b.purpose, b.user_id, b.status
        FROM bookings b
        JOIN classrooms c ON b.classroom_id = c.id
        JOIN users u ON b.user_id = u.id
        WHERE b.status = 'confirmed'
        ORDER BY b.booking_date DESC, b.start_time
        LIMIT 20
    """).fetchall()
    classrooms = db.execute("SELECT * FROM classrooms ORDER BY name").fetchall()
    db.close()
    user = current_user()
    
    return render_template_string(base_style + """
    <div class="container">
      <div class="nav">
        <div><strong>Smartboard Booking System</strong></div>
        <div>
          Welcome, {{user['full_name']}} ({{user['role']}}) |
          <a href="{{ url_for('profile') }}">Profile</a> |
          <a href="{{ url_for('logout') }}">Logout</a>
          {% if user['role']=='admin' %}
            | <a href="{{ url_for('admin') }}">Admin Panel</a>
          {% endif %}
        </div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}

      {% if user['role'] != 'faculty' %}
        <div class="small-muted">Only faculty accounts can create bookings. Admins can manage users and bookings in the Admin Panel.</div>
      {% else %}
        <h2>Make a Booking</h2>
        
        <div class="booking-note">
          <strong>📝 Note:</strong> Each booking slot is automatically set to 1 hour duration. 
          Select your preferred start time and the system will reserve the room until one hour later.
        </div>
        
        <form id="booking-form" method="post" action="{{ url_for('book') }}">
          <div class="form-group">
            <label>Classroom</label>
            <select name="classroom_id" id="classroom_id" required>
              {% for c in classrooms %}
                <option value="{{c['id']}}">{{c['name']}}</option>
              {% endfor %}
            </select>
          </div>
          <div style="display:flex; gap:10px;">
            <div style="flex:1" class="form-group">
              <label>Date</label>
              <input type="date" name="booking_date" id="booking_date" required>
            </div>
            <div style="flex:1" class="form-group">
              <label>Start Time (1 hour slot)</label>
              <select name="start_time" id="start_time" required>
                {% for time in time_slots %}
                  <option value="{{time}}">{{time}} - {{ calculate_end_time(time) }}</option>
                {% endfor %}
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>Purpose</label>
            <select name="purpose" id="purpose" required>
              <option value="Classroom Teaching">Classroom Teaching</option>
              <option value="Lab Teaching">Lab Teaching</option>
              <option value="Presentation">Presentation</option>
              <option value="Meeting">Meeting</option>
              <option value="Training">Training</option>
              <option value="Other">Other</option>
            </select>
          </div>
          <div style="margin-top:10px;">
            <button type="submit" id="book-btn" class="btn-success">Book Smartboard (1 Hour)</button>
            <button type="reset" style="background:#6c757d; margin-left:8px;">Reset</button>
            <span id="availability-msg" class="small-muted" style="margin-left:12px;"></span>
          </div>
        </form>
        <script>
        // Real-time availability check
        const form = document.getElementById('booking-form');
        const availMsg = document.getElementById('availability-msg');
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            const classroom_id = document.getElementById('classroom_id').value;
            const booking_date = document.getElementById('booking_date').value;
            const start_time = document.getElementById('start_time').value;
            if (!booking_date || !start_time) {
                availMsg.textContent = 'Please fill all fields.';
                return;
            }
            const resp = await fetch("{{ url_for('check_availability') }}", {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({classroom_id, booking_date, start_time})
            });
            const data = await resp.json();
            if (data.available) {
                availMsg.textContent = 'Slot available — creating booking...';
                form.removeEventListener('submit', arguments.callee);
                form.submit();
            } else {
                availMsg.textContent = 'Conflict: slot already booked.';
            }
        });
        </script>
      {% endif %}

      <h2 style="margin-top:20px;">Recent Bookings</h2>
      <table class="table">
        <thead><tr><th>Date</th><th>Time</th><th>Classroom</th><th>Booked by</th><th>Purpose</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>
          {% for b in bookings %}
            <tr>
              <td>{{ b['booking_date'] }}</td>
              <td>{{ b['start_time'] }} - {{ b['end_time'] }}</td>
              <td>{{ b['classroom'] }}</td>
              <td>{{ b['booked_by'] }}</td>
              <td>{{ b['purpose'] }}</td>
              <td><span class="status-{{ b['status'] }}">{{ b['status'].title() }}</span></td>
              <td>
                {% if user['role']=='admin' or b['user_id']==user['id'] %}
                  <form method="post" action="{{ url_for('cancel_booking', booking_id=b['id']) }}" style="display:inline">
                    <button type="submit" class="btn-danger" onclick="return confirm('Cancel this booking?')">Cancel</button>
                  </form>
                {% else %}
                  <span class="small-muted">—</span>
                {% endif %}
              </td>
            </tr>
          {% else %}
            <tr><td colspan="7">No bookings</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    """, bookings=bookings, classrooms=classrooms, user=user, time_slots=TIME_SLOTS, calculate_end_time=calculate_end_time)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    db = get_db()
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "update_notifications":
            email_notifications = 1 if request.form.get("email_notifications") else 0
            db.execute(
                "UPDATE users SET email_notifications = ? WHERE id = ?",
                (email_notifications, user["id"])
            )
            db.commit()
            flash("Notification preferences updated.", "success")
            
        elif action == "change_password":
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")
            
            if not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "error")
            elif new_password != confirm_password:
                flash("New passwords don't match.", "error")
            elif len(new_password) < 6:
                flash("Password must be at least 6 characters.", "error")
            else:
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), user["id"])
                )
                db.commit()
                flash("Password changed successfully.", "success")
        
        return redirect(url_for("profile"))
    
    # Get user's booking history
    user_bookings = db.execute("""
        SELECT b.id, c.name as classroom, b.booking_date, b.start_time, b.end_time, 
               b.purpose, b.status, b.created_at
        FROM bookings b
        JOIN classrooms c ON b.classroom_id = c.id
        WHERE b.user_id = ?
        ORDER BY b.booking_date DESC, b.start_time DESC
        LIMIT 10
    """, (user["id"],)).fetchall()
    
    db.close()
    
    email_notifications_value = user.get('email_notifications') if hasattr(user, 'get') else (user['email_notifications'] if 'email_notifications' in user.keys() else 1)
    
    return render_template_string(base_style + """
    <div class="container">
      <div class="nav">
        <h1>User Profile</h1>
        <div><a href="{{ url_for('index') }}">Back to Dashboard</a></div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}

      <div style="display: flex; gap: 20px;">
        <div style="flex: 1;">
          <h2>Profile Information</h2>
          <p><strong>Name:</strong> {{ user['full_name'] }}</p>
          <p><strong>Username:</strong> {{ user['username'] }}</p>
          <p><strong>Email:</strong> {{ user['email'] or 'Not set' }}</p>
          <p><strong>Role:</strong> {{ user['role'].title() }}</p>
          <p><strong>Member since:</strong> {{ user['created_at'][:10] }}</p>

          <h3>Email Notifications</h3>
          <form method="post">
            <input type="hidden" name="action" value="update_notifications">
            <label>
              <input type="checkbox" name="email_notifications" {{ 'checked' if email_notifications_value else '' }}>
              Receive email notifications for bookings and updates
            </label>
            <br><button type="submit" class="btn-success">Update Preferences</button>
          </form>

          <h3>Change Password</h3>
          <form method="post">
            <input type="hidden" name="action" value="change_password">
            <div class="form-group">
              <label>Current Password</label>
              <input type="password" name="current_password" required>
            </div>
            <div class="form-group">
              <label>New Password</label>
              <input type="password" name="new_password" required minlength="6">
            </div>
            <div class="form-group">
              <label>Confirm New Password</label>
              <input type="password" name="confirm_password" required minlength="6">
            </div>
            <button type="submit" class="btn-warning">Change Password</button>
          </form>
        </div>

        <div style="flex: 1;">
          <h2>My Recent Bookings</h2>
          <table class="table">
            <thead><tr><th>Date</th><th>Time</th><th>Room</th><th>Status</th></tr></thead>
            <tbody>
              {% for booking in user_bookings %}
                <tr>
                  <td>{{ booking['booking_date'] }}</td>
                  <td>{{ booking['start_time'] }} - {{ booking['end_time'] }}</td>
                  <td>{{ booking['classroom'] }}</td>
                  <td><span class="status-{{ booking['status'] }}">{{ booking['status'].title() }}</span></td>
                </tr>
              {% else %}
                <tr><td colspan="4">No bookings yet</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """, user=user, user_bookings=user_bookings, email_notifications_value=email_notifications_value)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        
        if not (username and email and password):
            flash("Please fill all fields.", "error")
            return redirect(url_for("register"))
        
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("register"))
        
        # Generate full name from username (capitalize and replace underscores/dots with spaces)
        full_name = username.replace('_', ' ').replace('.', ' ').title()
        
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username,email,password_hash,full_name,role) VALUES (?,?,?,?,?)",
                (username, email, generate_password_hash(password), full_name, "faculty")
            )
            db.commit()
            flash("Account created! You can now log in.", "success")
            
            # Send welcome email
            if email:
                subject = "Welcome to Smartboard Booking System"
                body = f"""Hello {full_name},

Welcome to the Smartboard Booking System!

Your account has been successfully created with the following details:
- Username: {username}
- Email: {email}
- Role: Faculty

You can now log in using your email address and password to book smartboard rooms for 1-hour slots.

Login URL: {request.url_root}login

If you have any questions, please contact the administrator.

Best regards,
Smartboard Booking System
"""
                queue_email(email, subject, body)
                send_email_async(email, subject, body)
            
            # Notify admin
            if ADMIN_EMAIL:
                send_admin_notification(
                    "New Faculty Registration",
                    f"New faculty member registered:\n\nName: {full_name}\nUsername: {username}\nEmail: {email}\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
            
            return redirect(url_for("login"))
            
        except sqlite3.IntegrityError:
            flash("Username or email already exists", "error")
        finally:
            db.close()
    
    return render_template_string(base_style + """
    <div class="container">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1>Faculty Registration</h1>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}

      <form method="post">
        <div class="form-group">
          <label>Username</label>
          <input name="username" required placeholder="Choose a username">
          <small class="small-muted">Your display name will be generated from your username</small>
        </div>
        <div class="form-group">
          <label>Email (College Email Recommended)</label>
          <input name="email" type="email" required placeholder="your.email@college.edu">
        </div>
        <div class="form-group">
          <label>Password (minimum 6 characters)</label>
          <input type="password" name="password" required minlength="6">
        </div>
        <button type="submit" class="btn-success">Register</button>
      </form>
      
      <div class="auth-links">
        <a href="{{ url_for('login') }}">Already have an account? Login</a>
        |
        <a href="{{ url_for('forgot_password') }}">Forgot Password?</a>
      </div>
    </div>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        
        db = get_db()
        # First try admin by username
        user = db.execute("SELECT * FROM users WHERE username = ?", (identifier,)).fetchone()
        if not user:
            # try faculty by email
            user = db.execute("SELECT * FROM users WHERE email = ?", (identifier.lower(),)).fetchone()
        db.close()
        
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials. Admins login with username; faculty login with email.", "error")
            return redirect(url_for("login"))
        
        # Set session
        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['full_name']}!", "success")
        
        # Send login notification
        send_login_notification(user)
        
        return redirect(url_for("index"))
    
    return render_template_string(base_style + """
    <div class="container">
      <h1>Login to Smartboard System</h1>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}
      
      <form method="post">
        <div class="form-group">
          <label>Username (Admin) or Email (Faculty)</label>
          <input name="identifier" required autofocus placeholder="username or email@college.edu">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required>
        </div>
        <div style="margin-top:8px;">
          <button type="submit" class="btn-success">Login</button>
          <a href="{{ url_for('forgot_password') }}" class="forgot-password-link">Forgot Password?</a>
        </div>
      </form>
      
      <div class="auth-links">
        <a href="{{ url_for('register') }}">New Faculty? Register Here</a>
      </div>
    </div>
    """)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        if not email:
            flash("Please enter your email address.", "error")
            return redirect(url_for("forgot_password"))
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        db.close()
        
        if user:
            # Create reset token
            token = create_password_reset_token(user["id"])
            
            # Send reset email
            if send_password_reset_link(user, token):
                flash("Password reset link sent to your email address.", "success")
            else:
                flash("Failed to send reset email. Please contact administrator.", "error")
        else:
            # Don't reveal if email exists or not for security
            flash("If an account with that email exists, a password reset link has been sent.", "info")
        
        return redirect(url_for("login"))
    
    return render_template_string(base_style + """
    <div class="container">
      <h1>Forgot Password</h1>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}
      
      <p>Enter your email address and we'll send you a link to reset your password.</p>
      
      <form method="post">
        <div class="form-group">
          <label>Email Address</label>
          <input name="email" type="email" required autofocus placeholder="your.email@college.edu">
        </div>
        <div style="margin-top:10px;">
          <button type="submit" class="btn-success">Send Reset Link</button>
        </div>
      </form>
      
      <div class="auth-links">
        <a href="{{ url_for('login') }}">Back to Login</a>
        |
        <a href="{{ url_for('register') }}">New Faculty? Register Here</a>
      </div>
    </div>
    """)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Verify token
    user_data = verify_reset_token(token)
    if not user_data:
        flash("Invalid or expired password reset link.", "error")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not password:
            flash("Please enter a new password.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirm_password:
            flash("Passwords don't match.", "error")
        else:
            # Update password
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), user_data["user_id"])
            )
            db.commit()
            db.close()
            
            # Mark token as used
            mark_token_used(token)
            
            flash("Password reset successfully! You can now log in.", "success")
            return redirect(url_for("login"))
    
    return render_template_string(base_style + """
    <div class="container">
      <h1>Reset Password</h1>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}
      
      <p>Enter a new password for your account: <strong>{{ user_data['full_name'] }}</strong></p>
      
      <form method="post">
        <div class="form-group">
          <label>New Password (minimum 6 characters)</label>
          <input type="password" name="password" required minlength="6" autofocus>
        </div>
        <div class="form-group">
          <label>Confirm New Password</label>
          <input type="password" name="confirm_password" required minlength="6">
        </div>
        <div style="margin-top:10px;">
          <button type="submit" class="btn-success">Reset Password</button>
        </div>
      </form>
      
      <div class="auth-links">
        <a href="{{ url_for('login') }}">Back to Login</a>
      </div>
    </div>
    """, user_data=user_data)