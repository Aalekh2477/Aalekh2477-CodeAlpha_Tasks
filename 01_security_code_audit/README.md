# Task 01 — Security Code Audit

> **CodeAlpha Cybersecurity Internship** | Application Security (AppSec)  
> **Difficulty:** ⭐⭐⭐ Intermediate | **Estimated Time:** 8–12 hours

---

## 🎯 Objective

Audit a deliberately vulnerable Flask application, identify **27 security flaws** across the **OWASP Top 10 (2021)**, and produce a fully remediated secure version with comprehensive documentation.

---

## 📂 Folder Structure

```
01_security_code_audit/
├── app.py                      # Vulnerable Flask app (27 intentional flaws)
├── app_secure.py               # Fully remediated secure version
├── SECURITY_AUDIT_REPORT.md    # Complete audit: 27 findings with CWE, severity, fixes
├── AUDIT_TOOLKIT.md            # SAST commands, CI/CD workflow, remediation patterns
├── app.db / app_secure.db      # SQLite databases (auto-created on run)
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip packages: `flask`, `pyyaml`, `requests`

```bash
cd 01_security_code_audit
pip install flask pyyaml requests
```

### 1️⃣ Run Vulnerable App (Training Only!)
```bash
python app.py
# → Opens http://localhost:5000
# ⚠️ NEVER expose this to any network. Use localhost only.
```

### 2️⃣ Run Secure Version
```bash
# Generate a strong secret key
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
# Windows PowerShell: $env:SECRET_KEY=(python -c "import secrets; print(secrets.token_hex(32))")

python app_secure.py
# → Opens http://localhost:5000 (secure)
```

### 3️⃣ Run Security Scans (SAST)
```bash
pip install bandit semgrep safety pip-audit

# Bandit (Python AST-based)
bandit -r app.py -f json -o bandit-report.json

# Semgrep (Pattern-based, multi-language)
semgrep --config=auto app.py --json=semgrep-report.json

# Safety (Known vulnerable dependencies)
safety check --json --output safety-report.json

# pip-audit (PyPI vulnerability database)
pip-audit --format=json --output pip-audit-report.json
```

---

## 🔍 Vulnerabilities Covered (27 Total)

| # | Category | Count | Severity | Example Location |
|---|----------|-------|----------|------------------|
| 1 | SQL Injection | 6 | Critical | `app.py:70, 85, 93, 156, 201, 245` |
| 2 | Cross-Site Scripting (XSS) | 4 | Critical | `app.py:79, 112, 188, 312` |
| 3 | Command Injection | 2 | Critical | `app.py:88, 267` |
| 4 | Insecure Deserialization | 2 | Critical | `app.py:97, 289` |
| 5 | XXE (XML External Entity) | 1 | High | `app.py:134` |
| 6 | SSRF (Server-Side Request Forgery) | 2 | High | `app.py:142, 150` |
| 7 | Path Traversal | 2 | High | `app.py:106, 223` |
| 8 | CSRF | 3 | High | `app.py:165, 178, 191` |
| 9 | IDOR / Broken Access Control | 4 | High | `app.py:198, 210, 234, 256` |
| 10 | Broken Authentication | 5 | High | `app.py:42, 58, 62, 301, 320` |
| 11 | Sensitive Data Exposure | 4 | High | `app.py:42, 58, 62, 330` |
| 12 | Security Misconfiguration | 3 | Medium | `app.py:42, 43, 340` |
| 13 | Insecure File Upload | 2 | High | `app.py:275, 282` |
| 14 | Race Condition | 1 | Medium | `app.py:350` |
| 15 | Insufficient Logging | 1 | Low | `app.py:82` |

**Total: 27 findings** — See [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md) for complete details.

---

## 🛡️ Key Remediation Patterns (Before → After)

### SQL Injection
```python
# ❌ VULNERABLE (app.py)
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# ✅ SECURE (app_secure.py)
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### XSS (Template Injection)
```python
# ❌ VULNERABLE
{{ content | safe }}

# ✅ SECURE
{{ content }}  # Jinja2 auto-escapes by default
```

### Command Injection
```python
# ❌ VULNERABLE
subprocess.run(f"ping {host}", shell=True)

# ✅ SECURE
subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)
```

### Insecure Deserialization
```python
# ❌ VULNERABLE
pickle.loads(user_data)

# ✅ SECURE
import json
json.loads(user_data)
```

### Path Traversal
```python
# ❌ VULNERABLE
filepath = os.path.join('/uploads', filename)

# ✅ SECURE
from werkzeug.utils import secure_filename
filename = secure_filename(filename)
filepath = os.path.join(UPLOAD_FOLDER, filename)
if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER)):
    raise ValueError("Path traversal attempt")
```

### Broken Authentication
```python
# ❌ VULNERABLE
# Plaintext passwords, hardcoded secret, no session validation

# ✅ SECURE
# bcrypt hashing, secrets.token_hex(32), Flask-Login, rate limiting, secure cookies
```

---

## 📊 Audit Report & Toolkit

| File | Purpose |
|------|---------|
| [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md) | 27 findings: CWE ID, file:line, severity, impact, PoC, fix code, verification steps |
| [`AUDIT_TOOLKIT.md`](AUDIT_TOOLKIT.md) | SAST command reference, CI/CD pipeline (GitHub Actions), remediation code snippets, tool comparison |

---

## 🧪 Testing Checklist

After running `app_secure.py`, verify:

- [ ] Login with `' OR 1=1--` **fails** (parameterized query)
- [ ] `<script>alert(1)</script>` in search **renders as text** (auto-escaped)
- [ ] `ping 8.8.8.8; cat /etc/passwd` **returns error** (no shell=True)
- [ ] `../../etc/passwd` in file upload **blocked** (secure_filename + path check)
- [ ] Admin panel **requires admin role** (RBAC enforced)
- [ ] Session **expires after 30 min** (secure cookie config)
- [ ] CSP header **present** in response (`Content-Security-Policy`)
- [ ] Rate limiting **active** on login (Flask-Limiter)

---

## 📚 Learning Resources

| Topic | Resource |
|-------|----------|
| OWASP Top 10 2021 | https://owasp.org/Top10/ |
| Flask Security | https://flask.palletsprojects.com/en/stable/security/ |
| Python Security | https://python-security.readthedocs.io/ |
| Bandit Docs | https://bandit.readthedocs.io/ |
| Semgrep Rules | https://semgrep.dev/docs/ |
| Secure Code Review | https://cheatsheetseries.owasp.org/cheatsheets/Code_Review_Cheat_Sheet.html |

---

## ⚠️ Safety Warning

> **The vulnerable `app.py` is for EDUCATIONAL PURPOSES ONLY.**
>
> - Contains: SQLi, XSS, RCE, XXE, SSRF, path traversal, auth bypass, and more
> - **NEVER** deploy to production, staging, or any network-accessible environment
> - Run only on **localhost** in an isolated VM/container
> - Delete `app.db` after testing — it contains plaintext passwords

---

## ✅ Submission Deliverables

- [ ] Vulnerable app (`app.py`) — pushed to GitHub
- [ ] Secure app (`app_secure.py`) — pushed to GitHub
- [ ] Audit report (`SECURITY_AUDIT_REPORT.md`) — 27 findings documented
- [ ] Toolkit (`AUDIT_TOOLKIT.md`) — SAST commands + CI/CD
- [ ] LinkedIn post with screenshots/video
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **[Master README](../README.md)** | **Task 02 →** [`../02_phishing_awareness_module/README.md`](../02_phishing_awareness_module/README.md)