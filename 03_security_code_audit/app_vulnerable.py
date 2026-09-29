#!/usr/bin/env python3
"""
Vulnerable Flask Application - For Security Code Review Training
================================================================
This application contains INTENTIONAL security vulnerabilities for educational purposes.
DO NOT deploy this in production!
"""

import os
import sqlite3
import hashlib
import subprocess
import pickle
from flask import Flask, request, render_template_string, session, redirect, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'  # VULN: Hardcoded secret
app.config['DEBUG'] = True  # VULN: Debug mode enabled

# Database initialization
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes
                 (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)''')
    
    # Insert default user with weak password
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        # VULN: Plaintext password storage
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                  ('admin', 'admin123', 'admin@example.com'))
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================
# VULNERABLE ROUTES
# ============================================================

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Notes App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/register">Register</a></li>
        <li><a href="/search">Search Notes</a></li>
        <li><a href="/upload">Upload File</a></li>
        <li><a href="/ping">Ping Tool</a></li>
        <li><a href="/deserialize">Deserialize Data</a></li>
    </ul>
    '''

# VULN 1: SQL Injection in login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        # VULN: SQL Injection via string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        return 'Invalid credentials'
    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    '''

# VULN 2: SQL Injection in search
@app.route('/search')
def search():
    q = request.args.get('q', '')
    conn = get_db()
    # VULN: SQL Injection
    query = f"SELECT * FROM notes WHERE content LIKE '%{q}%'"
    results = conn.execute(query).fetchall()
    conn.close()
    return render_template_string('''
    <h2>Search Results for "{{ q }}"</h2>
    <form><input name="q" value="{{ q }}"><button>Search</button></form>
    <ul>{% for r in results %}<li>{{ r.content }}</li>{% endfor %}</ul>
    ''', q=q, results=results)

# VULN 3: XSS in note creation
@app.route('/note', methods=['GET', 'POST'])
def note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        content = request.form['content']
        conn = get_db()
        conn.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", 
                     (session['user_id'], content))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return '''
    <form method="post">
        <textarea name="content"></textarea><br>
        <button type="submit">Save Note</button>
    </form>
    '''

# VULN 4: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        # VULN: Command injection via shell=True
        result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
        return f'<pre>{result.stdout}</pre><pre>{result.stderr}</pre>'
    return '''
    <form method="post">
        Host: <input name="host" value="8.8.8.8"><br>
        <button type="submit">Ping</button>
    </form>
    '''

# VULN 5: Insecure Deserialization
@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    if request.method == 'POST':
        data = request.form['data']
        # VULN: Pickle deserialization of user input
        obj = pickle.loads(bytes.fromhex(data))
        return f'Deserialized: {obj}'
    return '''
    <form method="post">
        Hex Pickle Data: <input name="data"><br>
        <button type="submit">Deserialize</button>
    </form>
    '''

# VULN 6: Path Traversal
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        # VULN: Path traversal - no filename validation
        filepath = os.path.join('/tmp/uploads', f.filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        f.save(filepath)
        return f'File saved to {filepath}'
    return '''
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file"><br>
        <button type="submit">Upload</button>
    </form>
    '''

# VULN 7: Broken Access Control (IDOR)
@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    # VULN: No ownership check - can view any user's note
    note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if note:
        return f'<h3>Note #{note_id}</h3><p>{note["content"]}</p>'
    return 'Note not found'

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    notes = conn.execute("SELECT * FROM notes WHERE user_id = ?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template_string('''
    <h2>Dashboard</h2>
    <ul>{% for n in notes %}<li><a href="/note/{{ n.id }}">{{ n.content[:50] }}</a></li>{% endfor %}</ul>
    <a href="/note">New Note</a> | <a href="/logout">Logout</a>
    ''', notes=notes)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)