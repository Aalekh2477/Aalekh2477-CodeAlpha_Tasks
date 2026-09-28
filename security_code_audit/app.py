#!/usr/bin/env python3
"""
Vulnerable Flask Application - FOR SECURITY AUDIT TRAINING ONLY
================================================================
This application contains INTENTIONAL security vulnerabilities for educational purposes.
DO NOT deploy this in production!

Vulnerabilities included:
- SQL Injection (multiple types)
- Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object References (IDOR)
- Broken Authentication & Session Management
- Security Misconfiguration
- Sensitive Data Exposure
- Insufficient Logging & Monitoring
- Path Traversal
- Command Injection
- Insecure Deserialization
- XXE (XML External Entity)
- Server-Side Request Forgery (SSRF)
- Race Conditions
- Information Disclosure
"""

import os
import sqlite3
import hashlib
import secrets
import subprocess
import xml.etree.ElementTree as ET
import pickle
import yaml
import requests
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, make_response, send_file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'  # VULN: Hardcoded secret
app.config['DEBUG'] = True  # VULN: Debug mode enabled in production

# Database initialization
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT, balance REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT, created_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, filename TEXT, path TEXT, user_id INTEGER)''')
    
    # Insert default admin user with weak password
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # VULN: Plaintext password storage (no hashing)
        c.execute("INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)",
                  ('admin', 'admin123', 'admin@example.com', 'admin', 10000.0))
        c.execute("INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)",
                  ('user1', 'password123', 'user1@example.com', 'user', 100.0))
        c.execute("INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)",
                  ('user2', 'qwerty', 'user2@example.com', 'user', 250.0))
    conn.commit()
    conn.close()

init_db()

# ============================================================
# VULNERABLE HELPER FUNCTIONS
# ============================================================

def get_db_connection():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_action(user_id, action):
    conn = get_db_connection()
    # VULN: SQL Injection via string formatting
    query = f"INSERT INTO logs (user_id, action, timestamp) VALUES ({user_id}, '{action}', datetime('now'))"
    conn.execute(query)
    conn.commit()
    conn.close()

def execute_query(query):
    """VULN: Generic query executor with no parameterization"""
    conn = get_db_connection()
    cursor = conn.execute(query)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

# ============================================================
# AUTHENTICATION & AUTHORIZATION VULNERABILITIES
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # VULN: No actual admin check - just checks if user_id exists
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULN: SQL Injection in login
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = get_db_connection()
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_action(user['id'], 'login')
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # VULN: SQL Injection in registration
        query = f"INSERT INTO users (username, password, email, role, balance) VALUES ('{username}', '{password}', '{email}', 'user', 0)"
        try:
            conn = get_db_connection()
            conn.execute(query)
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except:
            return 'Registration failed'
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ============================================================
# SQL INJECTION VULNERABILITIES
# ============================================================

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    
    # VULN: SQL Injection in search
    sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
    conn = get_db_connection()
    try:
        posts = conn.execute(sql).fetchall()
    except Exception as e:
        # VULN: Information disclosure via error messages
        return f"Error: {str(e)}<br>Query: {sql}"
    conn.close()
    
    return render_template_string(SEARCH_TEMPLATE, posts=posts, query=query)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    # VULN: IDOR - No authorization check, can view any user's profile
    # VULN: SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = get_db_connection()
    user = conn.execute(query).fetchone()
    conn.close()
    
    if user:
        return render_template_string(PROFILE_TEMPLATE, user=user)
    return 'User not found'

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # VULN: Race condition in balance transfer
    to_user = request.form['to_user']
    amount = float(request.form['amount'])
    
    conn = get_db_connection()
    
    # VULN: Non-atomic check-then-act (race condition)
    sender = conn.execute(f"SELECT balance FROM users WHERE id = {session['user_id']}").fetchone()
    if sender and sender['balance'] >= amount:
        # Simulate processing delay
        time.sleep(0.1)
        conn.execute(f"UPDATE users SET balance = balance - {amount} WHERE id = {session['user_id']}")
        conn.execute(f"UPDATE users SET balance = balance + {amount} WHERE username = '{to_user}'")
        conn.commit()
        log_action(session['user_id'], f'transferred {amount} to {to_user}')
        conn.close()
        return 'Transfer successful'
    conn.close()
    return 'Insufficient funds'

# ============================================================
# XSS VULNERABILITIES
# ============================================================

@app.route('/post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # VULN: Stored XSS - no sanitization
        query = f"INSERT INTO posts (user_id, title, content, created_at) VALUES ({session['user_id']}, '{title}', '{content}', datetime('now'))"
        conn = get_db_connection()
        conn.execute(query)
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    
    return render_template_string(CREATE_POST_TEMPLATE)

@app.route('/view_post/<int:post_id>')
@login_required
def view_post(post_id):
    # VULN: Stored XSS - content rendered without escaping
    query = f"SELECT * FROM posts WHERE id = {post_id}"
    conn = get_db_connection()
    post = conn.execute(query).fetchone()
    conn.close()
    
    if post:
        # VULN: Reflected XSS in referer
        referer = request.headers.get('Referer', '')
        return render_template_string(VIEW_POST_TEMPLATE, post=post, referer=referer)
    return 'Post not found'

@app.route('/comment', methods=['POST'])
@login_required
def add_comment():
    post_id = request.form['post_id']
    comment = request.form['comment']
    
    # VULN: DOM-based XSS via JSON response
    return jsonify({'comment': comment, 'status': 'success'})

# ============================================================
# CSRF VULNERABILITY
# ============================================================

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    # VULN: No CSRF protection
    new_password = request.form['new_password']
    query = f"UPDATE users SET password = '{new_password}' WHERE id = {session['user_id']}"
    conn = get_db_connection()
    conn.execute(query)
    conn.commit()
    conn.close()
    return 'Password changed'

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # VULN: No CSRF protection on account deletion
    query = f"DELETE FROM users WHERE id = {session['user_id']}"
    conn = get_db_connection()
    conn.execute(query)
    conn.commit()
    conn.close()
    session.clear()
    return redirect(url_for('login'))

# ============================================================
# COMMAND INJECTION
# ============================================================

@app.route('/ping', methods=['POST'])
@login_required
def ping():
    host = request.form['host']
    
    # VULN: Command injection via shell=True and string concatenation
    cmd = f"ping -c 4 {host}"
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        output = result.decode()
    except subprocess.CalledProcessError as e:
        output = e.output.decode()
    except Exception as e:
        output = str(e)
    
    return render_template_string(PING_TEMPLATE, output=output, host=host)

@app.route('/backup', methods=['POST'])
@admin_required
def backup():
    filename = request.form['filename']
    
    # VULN: Command injection with user-controlled filename
    cmd = f"tar -czf /backups/{filename}.tar.gz /var/www/app"
    try:
        subprocess.run(cmd, shell=True, check=True)
        return 'Backup created'
    except:
        return 'Backup failed'

# ============================================================
# PATH TRAVERSAL
# ============================================================

@app.route('/download')
@login_required
def download_file():
    filename = request.args.get('file', '')
    
    # VULN: Path traversal - no validation
    filepath = os.path.join('/app/uploads', filename)
    
    # VULN: Information disclosure - reveals if file exists
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return f"File not found: {filepath}"  # VULN: Path disclosure

@app.route('/read_file')
@login_required
def read_file():
    filepath = request.args.get('path', '')
    
    # VULN: Path traversal with directory traversal sequences
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except Exception as e:
        return f'Error reading file: {str(e)}'

# ============================================================
# INSECURE DESERIALIZATION
# ============================================================

@app.route('/deserialize', methods=['POST'])
@login_required
def deserialize_data():
    data = request.data
    
    # VULN: Insecure deserialization with pickle
    try:
        obj = pickle.loads(data)
        return f'Deserialized: {obj}'
    except Exception as e:
        return f'Error: {str(e)}'

@app.route('/yaml_load', methods=['POST'])
@login_required
def yaml_load():
    yaml_data = request.form['yaml']
    
    # VULN: Unsafe YAML loading (can execute code)
    try:
        data = yaml.load(yaml_data, Loader=yaml.Loader)  # VULN: Unsafe loader
        return f'Loaded: {data}'
    except Exception as e:
        return f'Error: {str(e)}'

# ============================================================
# XXE (XML External Entity)
# ============================================================

@app.route('/xml_parse', methods=['POST'])
@login_required
def xml_parse():
    xml_data = request.data
    
    # VULN: XXE - parser allows external entities
    parser = ET.XMLParser()
    parser.entity = {}  # Doesn't disable external entities properly
    try:
        root = ET.fromstring(xml_data, parser=parser)
        return f'Parsed: {ET.tostring(root).decode()}'
    except Exception as e:
        return f'Error: {str(e)}'

# ============================================================
# SSRF (Server-Side Request Forgery)
# ============================================================

@app.route('/fetch_url', methods=['POST'])
@login_required
def fetch_url():
    url = request.form['url']
    
    # VULN: SSRF - no validation of URL, can access internal services
    try:
        response = requests.get(url, timeout=5)
        return response.text[:1000]
    except Exception as e:
        return f'Error: {str(e)}'

@app.route('/proxy', methods=['GET'])
@login_required
def proxy():
    url = request.args.get('url')
    
    # VULN: SSRF - can access localhost, internal metadata services
    try:
        resp = requests.get(url, timeout=10)
        return resp.content, resp.status_code, resp.headers.items()
    except Exception as e:
        return str(e), 500

# ============================================================
# SENSITIVE DATA EXPOSURE
# ============================================================

@app.route('/api/users')
@login_required
def api_users():
    # VULN: Exposes all user data including passwords
    query = "SELECT * FROM users"
    conn = get_db_connection()
    users = conn.execute(query).fetchall()
    conn.close()
    
    # VULN: Returns sensitive data in API response
    return jsonify([dict(u) for u in users])

@app.route('/debug')
def debug_info():
    # VULN: Information disclosure - exposes environment, config
    return jsonify({
        'environment': dict(os.environ),
        'config': {k: v for k, v in app.config.items()},
        'session': dict(session),
        'request_headers': dict(request.headers)
    })

@app.route('/logs')
@admin_required
def view_logs():
    # VULN: SQL Injection in log filtering
    filter_user = request.args.get('user', '')
    query = f"SELECT * FROM logs WHERE user_id = '{filter_user}' ORDER BY timestamp DESC LIMIT 100"
    conn = get_db_connection()
    logs = conn.execute(query).fetchall()
    conn.close()
    return render_template_string(LOGS_TEMPLATE, logs=logs)

# ============================================================
# INSECURE FILE UPLOAD
# ============================================================

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    if file:
        # VULN: No file type validation, no secure filename
        filename = file.filename
        filepath = os.path.join('/app/uploads', filename)
        file.save(filepath)
        
        # VULN: SQL Injection
        query = f"INSERT INTO files (filename, path, user_id) VALUES ('{filename}', '{filepath}', {session['user_id']})"
        conn = get_db_connection()
        conn.execute(query)
        conn.commit()
        conn.close()
        
        return 'File uploaded'
    return 'No file'

# ============================================================
# INFORMATION DISCLOSURE / ERROR HANDLING
# ============================================================

@app.errorhandler(500)
def internal_error(error):
    # VULN: Detailed error messages in production
    return f"""
    <h1>Internal Server Error</h1>
    <p>Error: {str(error)}</p>
    <pre>{traceback.format_exc()}</pre>
    """, 500

# ============================================================
# BROKEN ACCESS CONTROL / IDOR
# ============================================================

@app.route('/api/user/<int:user_id>/balance')
@login_required
def get_balance(user_id):
    # VULN: IDOR - can check any user's balance
    # No check if user_id matches session user_id
    query = f"SELECT balance FROM users WHERE id = {user_id}"
    conn = get_db_connection()
    result = conn.execute(query).fetchone()
    conn.close()
    if result:
        return jsonify({'balance': result['balance']})
    return jsonify({'error': 'Not found'}), 404

@app.route('/admin/panel')
@admin_required
def admin_panel():
    # VULN: Weak admin check - only checks login, not role
    query = "SELECT * FROM users"
    conn = get_db_connection()
    users = conn.execute(query).fetchall()
    conn.close()
    return render_template_string(ADMIN_TEMPLATE, users=users)

# ============================================================
# SECURITY MISCONFIGURATION
# ============================================================

@app.route('/config')
def show_config():
    # VULN: Exposes configuration
    return jsonify({
        'secret_key': app.config['SECRET_KEY'],
        'debug': app.config['DEBUG'],
        'database': 'sqlite3',
        'version': '1.0'
    })

# ============================================================
# MAIN ROUTES
# ============================================================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    query = f"SELECT * FROM posts WHERE user_id = {session['user_id']} ORDER BY created_at DESC"
    conn = get_db_connection()
    posts = conn.execute(query).fetchall()
    conn.close()
    return render_template_string(DASHBOARD_TEMPLATE, posts=posts)

# ============================================================
# TEMPLATES (with XSS vulnerabilities)
# ============================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login</h2>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <p><a href="/register">Register</a></p>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Register</title></head>
<body>
    <h2>Register</h2>
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        Email: <input name="email"><br>
        <button type="submit">Register</button>
    </form>
</body>
</html>
"""

SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
    <h2>Search Posts</h2>
    <form method="GET">
        <input name="q" value="{{ query }}">
        <button type="submit">Search</button>
    </form>
    <hr>
    {% for post in posts %}
        <h3>{{ post['title'] }}</h3>
        <p>{{ post['content'] }}</p>
        <hr>
    {% endfor %}
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
    <h2>User Profile</h2>
    <p>Username: {{ user['username'] }}</p>
    <p>Email: {{ user['email'] }}</p>
    <p>Role: {{ user['role'] }}</p>
    <p>Balance: ${{ user['balance'] }}</p>
</body>
</html>
"""

CREATE_POST_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Create Post</title></head>
<body>
    <h2>Create Post</h2>
    <form method="POST">
        Title: <input name="title"><br>
        Content: <textarea name="content"></textarea><br>
        <button type="submit">Post</button>
    </form>
</body>
</html>
"""

VIEW_POST_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>{{ post['title'] }}</title></head>
<body>
    <h2>{{ post['title'] }}</h2>
    <p>{{ post['content'] | safe }}</p>
    <p>Referer: {{ referer }}</p>
    <hr>
    <form method="POST" action="/comment">
        <input type="hidden" name="post_id" value="{{ post['id'] }}">
        Comment: <input name="comment">
        <button type="submit">Comment</button>
    </form>
</body>
</html>
"""

PING_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Ping</title></head>
<body>
    <h2>Ping Tool</h2>
    <form method="POST">
        Host: <input name="host" value="{{ host }}">
        <button type="submit">Ping</button>
    </form>
    <pre>{{ output }}</pre>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h2>Welcome, {{ session.username }}</h2>
    <p><a href="/logout">Logout</a> | <a href="/search">Search</a> | <a href="/post">New Post</a></p>
    <hr>
    {% for post in posts %}
        <h3><a href="/view_post/{{ post['id'] }}">{{ post['title'] }}</a></h3>
        <p>{{ post['content'] | safe }}</p>
        <hr>
    {% endfor %}
</body>
</html>
"""

LOGS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Logs</title></head>
<body>
    <h2>System Logs</h2>
    <form method="GET">
        Filter by user: <input name="user" value="{{ request.args.get('user', '') }}">
        <button type="submit">Filter</button>
    </form>
    <table border="1">
        <tr><th>ID</th><th>User</th><th>Action</th><th>Time</th></tr>
        {% for log in logs %}
        <tr><td>{{ log['id'] }}</td><td>{{ log['user_id'] }}</td><td>{{ log['action'] }}</td><td>{{ log['timestamp'] }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h2>Admin Panel</h2>
    <table border="1">
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Password</th><th>Balance</th></tr>
        {% for user in users %}
        <tr>
            <td>{{ user['id'] }}</td>
            <td>{{ user['username'] }}</td>
            <td>{{ user['email'] }}</td>
            <td>{{ user['role'] }}</td>
            <td>{{ user['password'] }}</td>
            <td>${{ user['balance'] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

if __name__ == '__main__':
    import traceback
    app.run(host='0.0.0.0', port=5000, debug=True)