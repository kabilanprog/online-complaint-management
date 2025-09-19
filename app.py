from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = os.path.join(os.path.dirname(__file__), "database.db")

# ------------------ Database Helpers ------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Create tables if they don’t exist"""
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','technician','student')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        technician_id INTEGER,
        category TEXT NOT NULL,
        location TEXT,
        description TEXT,
        status TEXT DEFAULT 'Pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES users(id),
        FOREIGN KEY(technician_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        confirmed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """
    db = get_db()
    db.executescript(schema)
    db.commit()
    seed_users()

def seed_users():
    """Insert default admin and technicians if not already there"""
    db = get_db()
    cur = db.execute("SELECT COUNT(*) as c FROM users")
    count = cur.fetchone()["c"]
    if count == 0:
        users = [
            ('admin', generate_password_hash('admin123'), 'admin'),
            ('tech1', generate_password_hash('tech123'), 'technician'),
            ('tech2', generate_password_hash('tech123'), 'technician')
        ]
        db.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", users)
        db.commit()
        print("✅ Default users created: admin/admin123, tech1/tech123, tech2/tech123")

# ------------------ Auth Decorator ------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash("Unauthorized access", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ------------------ Routes ------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        db = get_db()
        cur = db.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Logged in successfully", "success")
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'technician':
                return redirect(url_for('technician_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        regno = request.form['regno'].strip()
        password = request.form['password'].strip()
        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE username = ?", (regno,))
        if cur.fetchone():
            flash("Registration number already used. Choose another.", "warning")
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (regno, pw_hash, 'student'))
        db.commit()
        flash("Registered successfully. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

# ------------------ Student ------------------
@app.route('/student/dashboard')
@login_required(role='student')
def student_dashboard():
    db = get_db()
    user_id = session['user']
    cur = db.execute("""SELECT c.*, u.username as student_username, t.username as technician_username 
                        FROM complaints c 
                        LEFT JOIN users u ON u.id = c.student_id 
                        LEFT JOIN users t ON t.id = c.technician_id 
                        WHERE c.student_id = ? ORDER BY c.created_at DESC""", (user_id,))
    complaints = cur.fetchall()
    cur = db.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    notifications = cur.fetchall()
    return render_template('student_dashboard.html', complaints=complaints, notifications=notifications)

@app.route('/submit_complaint', methods=['POST'])
@login_required(role='student')
def submit_complaint():
    category = request.form['category']
    location = request.form['location']
    description = request.form['description']
    db = get_db()
    db.execute("INSERT INTO complaints (student_id, category, location, description, status) VALUES (?, ?, ?, ?, ?)",
               (session['user'], category, location, description, 'Pending'))
    db.commit()
    flash("Complaint submitted", "success")
    return redirect(url_for('student_dashboard'))

@app.route('/confirm_notification/<int:noti_id>', methods=['POST'])
@login_required(role='student')
def confirm_notification(noti_id):
    db = get_db()
    db.execute("UPDATE notifications SET confirmed = 1 WHERE id = ? AND user_id = ?", (noti_id, session['user']))
    db.commit()
    flash("Notification confirmed. Thank you.", "success")
    return redirect(url_for('student_dashboard'))

# ------------------ Admin ------------------
@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    db = get_db()
    cur = db.execute("SELECT id, category, location, status, created_at, technician_id FROM complaints ORDER BY created_at DESC")
    complaints = cur.fetchall()
    techs = db.execute("SELECT id, username FROM users WHERE role = 'technician'").fetchall()
    return render_template('admin_dashboard.html', complaints=complaints, techs=techs)

@app.route('/assign_technician', methods=['POST'])
@login_required(role='admin')
def assign_technician():
    complaint_id = request.form['complaint_id']
    technician_id = request.form['technician_id']
    db = get_db()
    db.execute("UPDATE complaints SET technician_id = ? WHERE id = ?", (technician_id, complaint_id))
    db.commit()
    flash("Technician assigned", "success")
    return redirect(url_for('admin_dashboard'))

# ------------------ Technician ------------------
@app.route('/technician/dashboard')
@login_required(role='technician')
def technician_dashboard():
    db = get_db()
    tech_id = session['user']
    cur = db.execute("""SELECT c.*, u.username as student_username 
                        FROM complaints c 
                        LEFT JOIN users u ON u.id = c.student_id 
                        WHERE c.technician_id = ? ORDER BY c.created_at DESC""", (tech_id,))
    complaints = cur.fetchall()
    return render_template('technician_dashboard.html', complaints=complaints)

@app.route('/update_status', methods=['POST'])
@login_required(role='technician')
def update_status():
    complaint_id = request.form['complaint_id']
    status = request.form['status']
    db = get_db()
    db.execute("UPDATE complaints SET status = ? WHERE id = ?", (status, complaint_id))
    if status.lower() in ('solved', 'resolved', 'solved resolved'):
        cur = db.execute("SELECT student_id FROM complaints WHERE id = ?", (complaint_id,))
        row = cur.fetchone()
        if row:
            db.execute("INSERT INTO notifications (user_id, message, confirmed) VALUES (?, ?, ?)",
                       (row['student_id'], f"Your complaint #{complaint_id} marked as {status}. Please confirm.", 0))
    db.commit()
    flash("Status updated", "success")
    return redirect(url_for('technician_dashboard'))

# ------------------ Complaint Detail API ------------------
@app.route('/complaint/<int:cid>')
@login_required()
def complaint_detail(cid):
    db = get_db()
    cur = db.execute("""SELECT c.*, u.username as student_username, t.username as technician_username 
                        FROM complaints c 
                        LEFT JOIN users u ON u.id = c.student_id 
                        LEFT JOIN users t ON t.id = c.technician_id 
                        WHERE c.id = ?""", (cid,))
    c = cur.fetchone()
    if not c:
        return jsonify({'error':'Not found'}), 404
    return jsonify({k: c[k] for k in c.keys()})

# ------------------ Run ------------------
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
    else:
        with app.app_context():
            init_db()   # ensures tables & users exist
    app.run(host='0.0.0.0', port=5000, debug=True)
