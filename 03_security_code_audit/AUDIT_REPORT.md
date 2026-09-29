# Security Code Audit Report

**Application:** Vulnerable Notes App (Flask)  
**Language:** Python 3.x  
**Framework:** Flask  
**Date:** 2026-09-29  
**Auditor:** CodeAlpha Intern

---

## Executive Summary

A security code review was performed on a Flask-based notes application (`app_vulnerable.py`). **7 critical security vulnerabilities** were identified across OWASP Top 10 categories. A fully remediated version (`app_secure.py`) has been created with all vulnerabilities fixed.

---

## Findings Summary

| # | Vulnerability | Category | Severity | File:Line | Status |
|---|---------------|----------|----------|-----------|--------|
| 1 | SQL Injection (Login) | A03:2021 | Critical | app_vulnerable.py:52 | ✅ Fixed |
| 2 | SQL Injection (Search) | A03:2021 | Critical | app_vulnerable.py:78 | ✅ Fixed |
| 3 | Cross-Site Scripting (XSS) | A03:2021 | Critical | app_vulnerable.py:91 | ✅ Fixed |
| 4 | Command Injection | A03:2021 | Critical | app_vulnerable.py:106 | ✅ Fixed |
| 5 | Insecure Deserialization | A08:2021 | Critical | app_vulnerable.py:119 | ✅ Fixed |
| 5 | Path Traversal | A01:2021 | High | app_vulnerable.py:132 | ✅ Fixed |
| 7 | Broken Access Control (IDOR) | A01:2021 | High | app_vulnerable.py:145 | ✅ Fixed |
| 8 | Hardcoded Secret Key | A07:2021 | High | app_vulnerable.py:14 | ✅ Fixed |
| 9 | Debug Mode Enabled | A05:2021 | Medium | app_vulnerable.py:15 | ✅ Fixed |
| 10 | Plaintext Password Storage | A02:2021 | Critical | app_vulnerable.py:32 | ✅ Fixed |

---

## Detailed Findings

### 1. SQL Injection — Login (`app_vulnerable.py:52`)

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
user = conn.execute(query).fetchone()
```

**Impact:** Attacker can bypass authentication with `' OR 1=1--`

**Remediation:** Use parameterized queries
```python
user = conn.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
```

---

### 2. SQL Injection — Search (`app_vulnerable.py:78`)

**Vulnerable Code:**
```python
query = f"SELECT * FROM notes WHERE content LIKE '%{q}%'"
```

**Remediation:**
```python
results = conn.execute(
    "SELECT content FROM notes WHERE content LIKE ?", 
    (f'%{q}%',)
).fetchall()
```

---

### 3. Cross-Site Scripting (XSS) (`app_vulnerable.py:91`)

**Vulnerable Code:**
```python
conn.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", 
             (session['user_id'], content))  # No validation
```
Template renders with `{{ content }}` but no escaping in some contexts.

**Remediation:**
- Input validation: `if not content or len(content) > 5000: return 'Invalid'`
- Jinja2 auto-escaping enabled by default with `|e` filter
- Content-Security-Policy header

---

### 4. Command Injection (`app_vulnerable.py:106`)

**Vulnerable Code:**
```python
result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
```

**Impact:** Attacker inputs `8.8.8.8; cat /etc/passwd` → command execution

**Remediation:**
```python
result = subprocess.run(
    ['ping', '-c', '4', host], 
    capture_output=True, text=True, timeout=10
)
```

---

### 5. Insecure Deserialization (`app_vulnerable.py:119`)

**Vulnerable Code:**
```python
obj = pickle.loads(bytes.fromhex(data))
```

**Impact:** Remote code execution via malicious pickle payload

**Remediation:** Replace with JSON
```python
obj = json.loads(data)  # No code execution possible
```

---

### 6. Path Traversal (`app_vulnerable.py:132`)

**Vulnerable Code:**
```python
filepath = os.path.join('/tmp/uploads', f.filename)
```

**Impact:** Upload `../../etc/passwd` → arbitrary file write

**Remediation:**
```python
def sanitize_filename(filename):
    filename = Path(filename).name
    filename = "".join(c for c in filename if c.isalnum() or c in '.-_')
    return filename[:255]

# Check extension
allowed_ext = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.csv'}
```

---

### 7. Broken Access Control / IDOR (`app_vulnerable.py:145`)

**Vulnerable Code:**
```python
note = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```

**Impact:** Users can view other users' notes by changing ID

**Remediation:**
```python
note = conn.execute(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?", 
    (note_id, session['user_id'])
).fetchone()
```

---

### 8. Hardcoded Secret Key (`app_vulnerable.py:14`)

**Vulnerable Code:**
```python
app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'
```

**Remediation:**
```python
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
```

---

### 9. Debug Mode Enabled (`app_vulnerable.py:15`)

**Vulnerable Code:**
```python
app.config['DEBUG'] = True
```

**Remediation:**
```python
app.config['DEBUG'] = False
```

---

### 10. Plaintext Password Storage (`app_vulnerable.py:32`)

**Vulnerable Code:**
```python
c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
          ('admin', 'admin123', 'admin@example.com'))
```

**Remediation:**
```python
password_hash = hashlib.sha256(b'admin123').hexdigest()
# Use bcrypt in production: bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

---

## Tools Used

| Tool | Command | Purpose |
|------|---------|---------|
| **Bandit** | `bandit -r app_vulnerable.py` | Python AST-based SAST |
| **Semgrep** | `semgrep --config=auto app_vulnerable.py` | Pattern-based analysis |
| **Manual Review** | Line-by-line code inspection | Business logic flaws |

### Bandit Output Sample
```
>> Issue: [B608] Hardcoded SQL expressions
Severity: High   Confidence: High
Location: app_vulnerable.py:52

>> Issue: [B602] subprocess with shell=True
Severity: High   Confidence: High
Location: app_vulnerable.py:106
```

### Semgrep Output Sample
```
- rule: python.lang.security.audit.xss.xss-direct-concatenation
  severity: ERROR
  message: User input flows into render_template_string
```

---

## Recommendations & Best Practices

### Secure Coding Practices Applied

1. **Parameterized Queries** — Never concatenate user input into SQL
2. **Input Validation** — Validate type, length, format on all inputs
3. **Output Encoding** — Use template engine auto-escaping (`|e`)
4. **No `shell=True`** — Use argument lists for subprocess
5. **Safe Deserialization** — Use JSON, not pickle/marshal/yaml.load
6. **Path Sanitization** — Use `pathlib.Path`, validate extensions
7. **Access Control** — Verify ownership on every object access
8. **Secret Management** — Environment variables, not code
9. **Security Headers** — CSP, HSTS, X-Frame-Options, etc.
10. **Password Hashing** — bcrypt/argon2, never plaintext

### CI/CD Integration

```yaml
# .github/workflows/security.yml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
- run: pip install bandit semgrep safety pip-audit
- run: bandit -r . -f json -o bandit-report.json || true
- run: semgrep --config=auto . --json=semgrep-report.json || true
- run: safety check --json --output safety-report.json || true
- run: pip-audit --format=json --output pip-audit-report.json || true
```

---

## Verification Checklist

- [x] All SQL queries use parameterized statements
- [x] No `shell=True` in subprocess calls
- [x] No pickle/yaml.load of user data
- [x] File uploads validated and sanitized
- [x] Ownership verified on all object access
- [x] Secrets from environment variables
- [x] Debug mode disabled
- [x] Passwords hashed (bcrypt recommended for production)
- [x] Security headers implemented
- [x] Input validation on all user inputs
- [x] Output escaping in templates

---

## Files in This Audit

| File | Description |
|------|-------------|
| `app_vulnerable.py` | Original vulnerable application (7+ vulnerabilities) |
| `app_secure.py` | Fully remediated secure version |
| `AUDIT_REPORT.md` | This report |
| `README.md` | Setup and usage instructions |

---

## Conclusion

The vulnerable application contained **7 critical vulnerabilities** spanning OWASP Top 10 categories A01, A02, A03, A05, A07, A08. All have been remediated in `app_secure.py` following secure coding best practices. The secure version implements defense-in-depth with parameterized queries, input validation, output encoding, secure headers, and proper access controls.

**Recommendation:** Integrate SAST tools (Bandit, Semgrep) into CI/CD pipeline to prevent regression.