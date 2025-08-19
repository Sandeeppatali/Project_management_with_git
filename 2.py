from flask import Flask, request, redirect, url_for, render_template_string, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "supersecretkey")
DB_FILE = "smartboard.db"

# Optional SMTP config (set env vars to enable email sending)
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT")) if os.environ.get("SMTP_PORT") else None
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

# ---------- DATABASE SETUP ----------
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    # enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    db = get_db()
    # users: admin or faculty
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','faculty'))
    )""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS classrooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )""")
    db.execute("""
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        classroom_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        booking_date TEXT NOT NULL,    -- YYYY-MM-DD
        start_time TEXT NOT NULL,      -- HH:MM
        end_time TEXT NOT NULL,        -- HH:MM
        purpose TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY(classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")
    # seed admin if none exists
    c = db.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
    if c == 0:
        db.execute(
            "INSERT INTO users (username,email,password_hash,full_name,role) VALUES (?,?,?,?,?)",
            ("admin", None, generate_password_hash("admin123"), "Administrator", "admin")
        )
    # seed classrooms
    c = db.execute("SELECT COUNT(*) AS c FROM classrooms").fetchone()["c"]
    if c == 0:
        db.executemany("INSERT INTO classrooms (name) VALUES (?)",
                       [("Smartboard Room 1",), ("Smartboard Room 2",)])
    db.commit()
    db.close()

# ---------- EMAIL HELPER ----------
def send_email(to_address, subject, body):
    """Try to send email; returns True if sent, False otherwise (including if SMTP not configured)."""
    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS and SMTP_FROM):
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_address
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        app.logger.warning("Failed to send email: %s", e)
        return False

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
        "SELECT start_time, end_time FROM bookings WHERE classroom_id = ? AND booking_date = ?",
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
input, select, button { padding: 8px; margin: 6px 0; border-radius: 6px; border: 1px solid #ccc; }
button { background: #007bff; color: white; cursor: pointer; }
button:hover { opacity: 0.95; }
.table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.table th, .table td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; }
.flash { padding: 10px; margin-bottom: 12px; border-radius: 6px; }
.flash.error { background: #f8d7da; color: #721c24; }
.flash.success { background: #d4edda; color: #155724; }
.small-muted { color: #6c757d; font-size: 0.9rem; }
.nav { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
.nav a { margin-left:8px; color:#007bff; text-decoration:none; }
</style>
"""

# ---------- ROUTES ----------
@app.route("/")
@login_required
def index():
    db = get_db()
    bookings = db.execute("""
        SELECT b.id, c.name as classroom, u.full_name as booked_by,
               b.booking_date, b.start_time, b.end_time, b.purpose, b.user_id
        FROM bookings b
        JOIN classrooms c ON b.classroom_id = c.id
        JOIN users u ON b.user_id = u.id
        ORDER BY b.booking_date DESC, b.start_time
    """).fetchall()
    classrooms = db.execute("SELECT * FROM classrooms ORDER BY name").fetchall()
    db.close()
    user = current_user()
    # Admin should not see booking form
    return render_template_string(base_style + """
    <div class="container">
      <div class="nav">
        <div><strong>Smartboard Booking</strong></div>
        <div>
          Welcome, {{user['full_name']}} ({{user['role']}}) |
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
        <form id="booking-form" method="post" action="{{ url_for('book') }}">
          <label>Classroom</label>
          <select name="classroom_id" id="classroom_id" required>
            {% for c in classrooms %}
              <option value="{{c['id']}}">{{c['name']}}</option>
            {% endfor %}
          </select>
          <div style="display:flex; gap:10px;">
            <div style="flex:1">
              <label>Date</label>
              <input type="date" name="booking_date" id="booking_date" required>
            </div>
            <div style="flex:1">
              <label>Start</label>
              <input type="time" name="start_time" id="start_time" required>
            </div>
            <div style="flex:1">
              <label>End</label>
              <input type="time" name="end_time" id="end_time" required>
            </div>
          </div>
          <label>Purpose</label>
          <select name="purpose" id="purpose" required>
            <option value="Classroom Teaching">Classroom Teaching</option>
            <option value="Lab Teaching">Lab Teaching</option>
          </select>
          <div style="margin-top:10px;">
            <button type="submit" id="book-btn">Book Smartboard</button>
            <button type="reset" style="background:#6c757d; margin-left:8px;">Reset</button>
            <span id="availability-msg" class="small-muted" style="margin-left:12px;"></span>
          </div>
        </form>
        <script>
        // Real-time availability check before submission
        const form = document.getElementById('booking-form');
        const availMsg = document.getElementById('availability-msg');
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            const classroom_id = document.getElementById('classroom_id').value;
            const booking_date = document.getElementById('booking_date').value;
            const start_time = document.getElementById('start_time').value;
            const end_time = document.getElementById('end_time').value;
            if (!booking_date || !start_time || !end_time) {
                availMsg.textContent = 'Please fill date/time.';
                return;
            }
            const resp = await fetch("{{ url_for('check_availability') }}", {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({classroom_id, booking_date, start_time, end_time})
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
        <thead><tr><th>Date</th><th>Time</th><th>Classroom</th><th>Booked by</th><th>Purpose</th><th>Action</th></tr></thead>
        <tbody>
          {% for b in bookings %}
            <tr>
              <td>{{ b['booking_date'] }}</td>
              <td>{{ b['start_time'] }} - {{ b['end_time'] }}</td>
              <td>{{ b['classroom'] }}</td>
              <td>{{ b['booked_by'] }}</td>
              <td>{{ b['purpose'] }}</td>
              <td>
                {% if user['role']=='admin' or b['user_id']==user['id'] %}
                  <form method="post" action="{{ url_for('cancel_booking', booking_id=b['id']) }}" style="display:inline">
                    <button type="submit" onclick="return confirm('Cancel this booking?')">Cancel</button>
                  </form>
                {% else %}
                  <span class="small-muted">—</span>
                {% endif %}
              </td>
            </tr>
          {% else %}
            <tr><td colspan="6">No bookings</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    """, bookings=bookings, classrooms=classrooms, user=user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not (full_name and username and email and password):
            flash("Please fill all fields, including email (required for faculty).", "error")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,email,password_hash,full_name,role) VALUES (?,?,?,?,?)",
                       (username, email, generate_password_hash(password), full_name, "faculty"))
            db.commit()
            flash("Account created! You can log in using your email.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists", "error")
        finally:
            db.close()
    return render_template_string(base_style + """
    <div class="container">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1>Faculty Signup</h1>
        <div><a href="{{ url_for('login') }}">Login</a></div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}

      <form method="post">
        <label>Full Name</label><input name="full_name" required>
        <label>Username</label><input name="username" required>
        <label>Email (college email recommended)</label><input name="email" type="email" required>
        <label>Password</label><input type="password" name="password" required>
        <button type="submit">Register</button>
      </form>
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
        # If faculty, ensure they logged in with their email (we used identifier lookup above)
        if user["role"] == "faculty" and (not user["email"]):
            flash("Faculty account must have an email set. Contact admin.", "error")
            return redirect(url_for("login"))
        # set session
        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome, {user['full_name']}!", "success")
        # send notification for faculty login
        if user["role"] == "faculty":
            if user["email"]:
                sent = send_email(
                    user["email"],
                    "Login notification - Smartboard",
                    f"Hello {user['full_name']},\n\nYou have just logged into the Smartboard booking system at {datetime.utcnow().isoformat()}Z.\n\nIf this wasn't you, contact admin."
                )
                if sent:
                    flash("Login notification email sent.", "success")
                else:
                    flash("Login notification not sent (SMTP not configured).", "error")
        return redirect(url_for("index"))
    return render_template_string(base_style + """
    <div class="container">
      <h1>Login</h1>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}
      <form method="post">
        <label>Admin: use username | Faculty: use email</label>
        <input name="identifier" required autofocus placeholder="username or email">
        <label>Password</label>
        <input type="password" name="password" required>
        <div style="margin-top:8px;">
          <button type="submit">Login</button>
          <a href="{{ url_for('register') }}" style="margin-left:12px;">Register (faculty)</a>
        </div>
      </form>
    </div>
    """)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

@app.route("/check_availability", methods=["POST"])
@login_required
def check_availability():
    data = request.get_json() or {}
    classroom_id = data.get("classroom_id")
    booking_date = data.get("booking_date")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    if not (classroom_id and booking_date and start_time and end_time):
        return jsonify({"available": False, "error": "missing fields"}), 400
    db = get_db()
    conflict = booking_conflict(db, classroom_id, booking_date, start_time, end_time)
    db.close()
    return jsonify({"available": not conflict})

@app.route("/book", methods=["POST"])
@login_required
def book():
    user = current_user()
    # only faculty can create bookings
    if user["role"] != "faculty":
        flash("Only faculty can create bookings.", "error")
        return redirect(url_for("index"))

    classroom_id = request.form.get("classroom_id")
    booking_date = request.form.get("booking_date")
    start_time = request.form.get("start_time")
    end_time = request.form.get("end_time")
    purpose = request.form.get("purpose") or "Classroom Teaching"

    # validate input
    if not (classroom_id and booking_date and start_time and end_time):
        flash("Please fill required fields.", "error")
        return redirect(url_for("index"))
    try:
        st = datetime.strptime(start_time, "%H:%M")
        et = datetime.strptime(end_time, "%H:%M")
        if et <= st:
            flash("End time must be after start time.", "error")
            return redirect(url_for("index"))
    except Exception:
        flash("Invalid time format.", "error")
        return redirect(url_for("index"))

    db = get_db()
    # check conflict
    if booking_conflict(db, classroom_id, booking_date, start_time, end_time):
        db.close()
        flash("Time overlaps with an existing booking.", "error")
        return redirect(url_for("index"))
    db.execute(
        "INSERT INTO bookings (classroom_id, user_id, booking_date, start_time, end_time, purpose) VALUES (?,?,?,?,?,?)",
        (classroom_id, user["id"], booking_date, start_time, end_time, purpose)
    )
    db.commit()
    db.close()
    flash("Booking confirmed", "success")
    return redirect(url_for("index"))

@app.route("/cancel/<int:booking_id>", methods=["POST"])
@login_required
def cancel_booking(booking_id):
    user = current_user()
    db = get_db()
    booking = db.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()
    if not booking:
        flash("Booking not found", "error")
        db.close()
        return redirect(url_for("index"))
    if user["role"] == "admin" or booking["user_id"] == user["id"]:
        db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
        db.commit()
        flash("Booking cancelled", "success")
    else:
        flash("You cannot cancel this booking", "error")
    db.close()
    return redirect(url_for("index"))

# ---------- ADMIN PANEL ----------
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "reset_password":
            uid = request.form.get("user_id")
            if uid:
                target = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
                if target:
                    if target["role"] == "admin":
                        flash("Cannot reset another admin's password here.", "error")
                    else:
                        temp = generate_temp_password(10)
                        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(temp), uid))
                        db.commit()
                        # try email
                        if target["email"]:
                            sent = send_email(target["email"], "Temporary password - Smartboard", f"Hello {target['full_name']},\n\nYour temporary password: {temp}\nPlease login and change it.")
                            if sent:
                                flash("Temporary password emailed to faculty.", "success")
                            else:
                                flash(f"Email not sent (SMTP not configured). Temporary password: {temp}", "success")
                        else:
                            flash(f"No email on file. Temporary password: {temp}", "success")
        elif action == "delete_user":
            uid = request.form.get("user_id")
            if uid:
                if int(uid) == session.get("user_id"):
                    flash("You cannot delete yourself.", "error")
                else:
                    db.execute("DELETE FROM users WHERE id = ?", (uid,))
                    db.commit()
                    flash("User deleted (and their bookings).", "success")
        elif action == "add_classroom":
            name = request.form.get("name", "").strip()
            if name:
                try:
                    db.execute("INSERT INTO classrooms (name) VALUES (?)", (name,))
                    db.commit()
                    flash("Classroom added.", "success")
                except sqlite3.IntegrityError:
                    flash("Classroom name must be unique.", "error")
            else:
                flash("Name required.", "error")

    classrooms = db.execute("SELECT * FROM classrooms ORDER BY name").fetchall()
    users = db.execute("SELECT id, username, email, full_name, role FROM users ORDER BY role DESC, username").fetchall()
    bookings = db.execute("""
        SELECT b.id, b.booking_date, b.start_time, b.end_time, c.name as classroom, u.full_name as booked_by
        FROM bookings b
        JOIN classrooms c ON c.id = b.classroom_id
        JOIN users u ON u.id = b.user_id
        ORDER BY b.booking_date DESC, b.start_time
    """).fetchall()
    db.close()

    return render_template_string(base_style + """
    <div class="container">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1>Admin Panel</h1>
        <div><a href="{{ url_for('index') }}">Back</a></div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{message}}</div>
        {% endfor %}
      {% endwith %}

      <h2>Classrooms</h2>
      <form method="post" style="display:flex; gap:8px; align-items:center;">
        <input name="name" placeholder="Room name (e.g., CS-101)" required>
        <input type="hidden" name="action" value="add_classroom">
        <button type="submit">Add</button>
      </form>
      <ul>
        {% for c in classrooms %}
          <li><strong>{{ c['name'] }}</strong></li>
        {% endfor %}
      </ul>

      <h2>Users</h2>
      <table class="table">
        <thead><tr><th>Username</th><th>Full name</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody>
          {% for u in users %}
            <tr>
              <td>{{ u['username'] or '' }}</td>
              <td>{{ u['full_name'] }}</td>
              <td>{{ u['email'] or '' }}</td>
              <td>{{ u['role'] }}</td>
              <td>
                <form method="post" style="display:inline">
                  <input type="hidden" name="action" value="reset_password">
                  <input type="hidden" name="user_id" value="{{ u['id'] }}">
                  <button type="submit">Reset Password</button>
                </form>
                <form method="post" style="display:inline" onsubmit="return confirm('Delete user?');">
                  <input type="hidden" name="action" value="delete_user">
                  <input type="hidden" name="user_id" value="{{ u['id'] }}">
                  <button type="submit">Delete</button>
                </form>
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>

      <h2>All Bookings</h2>
      <table class="table">
        <thead><tr><th>Date</th><th>Time</th><th>Classroom</th><th>By</th><th></th></tr></thead>
        <tbody>
          {% for b in bookings %}
            <tr>
              <td>{{ b['booking_date'] }}</td>
              <td>{{ b['start_time'] }} - {{ b['end_time'] }}</td>
              <td>{{ b['classroom'] }}</td>
              <td>{{ b['booked_by'] }}</td>
              <td>
                <form method="post" action="{{ url_for('cancel_booking', booking_id=b['id']) }}">
                  <button type="submit">Cancel</button>
                </form>
              </td>
            </tr>
          {% else %}
            <tr><td colspan="5">No bookings</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    """, classrooms=classrooms, users=users, bookings=bookings)

# ---------- START ----------
if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        init_db()
    else:
        # just ensure DB exists and has required schema
        init_db()
    app.run(debug=True)
