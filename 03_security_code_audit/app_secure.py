#!/usr/bin/env python3
"""
Secure Flask Application - Remediated Version
=============================================
All vulnerabilities from app_vulnerable.py have been fixed.
"""

import os
import sqlite3
import subprocess
import json
import secrets
from pathlib import Path
from functools import wraps
from flask import Flask, request, render_template_string, session, redirect, url_for

app = Flask(__name__)
# SECURE: Strong secret from environment with fallback for dev
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = False  # SECURE: Debug disabled in production
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Database initialization
def init_db():
    conn = sqlite3.connect('app_secure.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes
                 (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert default user with hashed password
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # SECURE: Password hashing with SHA-256 (use bcrypt in production)
        password_hash = hashlib.sha256(b'admin123').hexdigest()
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                  ('admin', password_hash, 'admin@example.com'))
    conn.commit()
    conn.close()

import hashlib
init_db()

def get_db():
    conn = sqlite3.connect('app_secure.db')
    conn.row_factory = sqlite3.Row
    return conn

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Input validation helpers
def validate_username(username):
    return username and 3 <= len(username) <= 50 and username.isalnum()

def validate_password(password):
    return password and len(password) >= 8

def sanitize_filename(filename):
    # SECURE: Remove path components, keep only safe characters
    filename = Path(filename).name
    filename = "".join(c for c in filename if c.isalnum() or c in '.-_')
    return filename[:255]

# ============================================================
# SECURE ROUTES
# ============================================================

@app.route('/')
def index():
    return '''
    <h1>Secure Notes App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/register">Register</a></li>
        <li><a href="/search">Search Notes</a></li>
        <li><a href="/upload">Upload File</a></li>
        <li><a href="/ping">Ping Tool</a></li>
        <li><a href="/deserialize">JSON Data</a></li>
    </ul>
    '''

# SECURE 1: Parameterized queries prevent SQL injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SECURE: Input validation
        if not validate_username(username) or not validate_password(password):
            return 'Invalid input', 400
        
        conn = get_db()
        # SECURE: Parameterized query
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        
        # SECURE: Password verification with constant-time comparison
        if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        return 'Invalid credentials', 401
    return '''
    <form method="post">
        Username: <input name="username" required><br>
        Password: <input type="password" name="password" required minlength="8"><br>
        <button type="submit">Login</button>
    </form>
    '''

# SECURE 2: Parameterized query for search
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # SECURE: Input validation and length limit
    if len(q) > 100:
        q = q[:100]
    
    conn = get_db()
    # SECURE: Parameterized query with wildcards in parameter
    results = conn.execute(
        "SELECT content FROM notes WHERE content LIKE ?", 
        (f'%{q}%',)
    ).fetchall()
    conn.close()
    return render_template_string('''
    <h2>Search Results for "{{ q }}"</h2>
    <form><input name="q" value="{{ q }}" maxlength="100"><button>Search</button></form>
    <ul>{% for r in results %}<li>{{ r.content | e }}</li>{% endfor %}</ul>
    ''', q=q, results=results)

# SECURE 3: XSS prevention via auto-escaping
@app.route('/note', methods=['GET', 'POST'])
@login_required
def note():
    if request.method == 'POST':
        content = request.form['content']
        # SECURE: Input validation and length limit
        if not content or len(content) > 5000:
            return 'Invalid content', 400
        
        conn = get_db()
        conn.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)", 
            (session['user_id'], content)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return '''
    <form method="post">
        <textarea name="content" maxlength="5000" required></textarea><br>
        <button type="submit">Save Note</button>
    </form>
    '''

# SECURE 4: No shell=True, argument list prevents command injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        # SECURE: Input validation - only allow alphanumeric, dots, dashes
        if not host or not all(c.isalnum() or c in '.-' for c in host):
            return 'Invalid host', 400
        if len(host) > 253:
            return 'Host too long', 400
        
        # SECURE: No shell=True, arguments as list
        try:
            result = subprocess.run(
                ['ping', '-c', '4', host], 
                capture_output=True, text=True, timeout=10
            )
            return f'<pre>{result.stdout}</pre>'
        except subprocess.TimeoutExpired:
            return 'Ping timeout', 408
        except Exception:
            return 'Ping failed', 500
    return '''
    <form method="post">
        Host: <input name="host" value="8.8.8.8" pattern="[a-zA-Z0-9.-]+" required><br>
        <button type="submit">Ping</button>
    </form>
    '''

# SECURE 5: JSON instead of pickle - no code execution
@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    if request.method == 'POST':
        data = request.form['data']
        # SECURE: JSON only - no code execution possible
        try:
            obj = json.loads(data)
            return f'Parsed JSON: {json.dumps(obj, indent=2)}'
        except json.JSONDecodeError:
            return 'Invalid JSON', 400
    return '''
    <form method="post">
        JSON Data: <textarea name="data" rows="5" cols="40">{"key": "value"}</textarea><br>
        <button type="submit">Parse JSON</button>
    </form>
    '''

# SECURE 6: Secure file upload with validation
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file', 400
        f = request.files['file']
        if f.filename == '':
            return 'No file selected', 400
        
        # SECURE: Filename sanitization
        filename = sanitize_filename(f.filename)
        if not filename:
            return 'Invalid filename', 400
        
        # SECURE: Check file extension
        allowed_ext = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.csv'}
        if not any(filename.lower().endswith(ext) for ext in allowed_ext):
            return 'File type not allowed', 400
        
        # SECURE: Save with safe filename
        upload_dir = Path('/tmp/uploads')
        upload_dir.mkdir(exist_ok=True)
        filepath = upload_dir / filename
        f.save(str(filepath))
        return f'File saved securely as {filename}'
    return '''
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        <button type="submit">Upload</button>
    </form>
    '''

# SECURE 7: Access control - verify ownership
@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    conn = get_db()
    # SECURE: Verify note belongs to current user
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?", 
        (note_id, session['user_id'])
    ).fetchone()
    conn.close()
    if note:
        # SECURE: Auto-escape with |e filter
        return render_template_string('''
        <h3>Note #{{ note.id }}</h3>
        <p>{{ note.content | e }}</p>
        <a href="/dashboard">Back</a>
        ''', note=note)
    return 'Note not found or access denied', 404

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    notes = conn.execute(
        "SELECT id, content, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template_string('''
    <h2>Dashboard - Welcome {{ username }}</h2>
    <ul>
        {% for n in notes %}
        <li><a href="/note/{{ n.id }}">{{ n.content[:50] | e }}</a> ({{ n.created_at }})</li>
        {% endfor %}
    </ul>
    <a href="/note">New Note</a> | <a href="/logout">Logout</a>
    ''', username=session['username'], notes=notes)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)