# Task 03 — Secure Coding Review

> **CodeAlpha Cybersecurity Internship** | Application Security (AppSec)  
> **Difficulty:** ⭐⭐⭐ Intermediate | **Estimated Time:** 4–6 hours

---

## 🎯 Objective

Perform a security code review on a vulnerable Flask application, identify vulnerabilities using static analysis tools and manual inspection, and produce a fully remediated secure version with documented findings.

---

## 📂 Folder Structure

```
03_security_code_audit/
├── app_vulnerable.py    # Vulnerable Flask app (7+ vulnerabilities)
├── app_secure.py        # Fully remediated secure version
├── AUDIT_REPORT.md      # Complete audit findings with remediation
└── README.md            # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip packages: `flask`

```bash
cd 03_security_code_audit
pip install flask
```

### 1️⃣ Run Vulnerable App (Training Only!)
```bash
python app_vulnerable.py
# → Opens http://localhost:5000
# ⚠️ NEVER expose this to any network. Use localhost only.
```

### 2️⃣ Run Secure Version
```bash
# Generate a strong secret key
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
# Windows PowerShell: $env:SECRET_KEY=(python -c "import secrets; print(secrets.token_hex(32))")

python app_secure.py
# → Opens http://127.0.0.1:5000 (secure)
```

### 3️⃣ Run Security Scans (SAST)
```bash
pip install bandit semgrep safety pip-audit

# Bandit (Python AST-based)
bandit -r app_vulnerable.py

# Semgrep (Pattern-based)
semgrep --config=auto app_vulnerable.py

# Safety (Known vulnerable dependencies)
safety check

# pip-audit (PyPI vulnerability database)
pip-audit
```

---

## 🔍 Vulnerabilities Covered

| # | Vulnerability | OWASP Category | Severity | Location |
|---|---------------|----------------|----------|----------|
| 1 | SQL Injection (Login) | A03:2021 | Critical | `app_vulnerable.py:52` |
| 2 | SQL Injection (Search) | A03:2021 | Critical | `app_vulnerable.py:78` |
| 3 | Cross-Site Scripting (XSS) | A03:2021 | Critical | `app_vulnerable.py:91` |
| 4 | Command Injection | A03:2021 | Critical | `app_vulnerable.py:106` |
| 5 | Insecure Deserialization | A08:2021 | Critical | `app_vulnerable.py:119` |
| 6 | Path Traversal | A01:2021 | High | `app_vulnerable.py:132` |
| 7 | Broken Access Control (IDOR) | A01:2021 | High | `app_vulnerable.py:145` |
| 8 | Hardcoded Secret Key | A07:2021 | High | `app_vulnerable.py:14` |
| 9 | Debug Mode Enabled | A05:2021 | Medium | `app_vulnerable.py:15` |
| 10 | Plaintext Password Storage | A02:2021 | Critical | `app_vulnerable.py:32` |

---

## 🛡️ Key Remediation Patterns

### SQL Injection
```python
# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"

# ✅ SECURE
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### Command Injection
```python
# ❌ VULNERABLE
subprocess.run(f"ping {host}", shell=True)

# ✅ SECURE
subprocess.run(['ping', '-c', '4', host], capture_output=True)
```

### XSS Prevention
```python
# ❌ VULNERABLE
return render_template_string('<h1>' + user_input + '</h1>')

# ✅ SECURE
return render_template_string('<h1>{{ input | e }}</h1>', input=user_input)
```

### Insecure Deserialization
```python
# ❌ VULNERABLE
pickle.loads(user_data)

# ✅ SECURE
json.loads(user_data)  # No code execution
```

### Path Traversal
```python
# ❌ VULNERABLE
filepath = os.path.join('/uploads', filename)

# ✅ SECURE
filename = Path(filename).name
if filename.suffix not in allowed_ext: raise ValueError()
```

### Broken Access Control
```python
# ❌ VULNERABLE
note = db.execute("SELECT * FROM notes WHERE id = ?", (id,))

# ✅ SECURE
note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?", (id, user_id))
```

---

## 📊 Audit Report

See [`AUDIT_REPORT.md`](AUDIT_REPORT.md) for:
- Detailed findings with code snippets
- Tool output samples (Bandit, Semgrep)
- Complete remediation guide
- CI/CD integration example
- Verification checklist

---

## 🧪 Testing Checklist

After running `app_secure.py`, verify:

- [ ] Login with `' OR 1=1--` **fails** (parameterized query)
- [ ] Search with `<script>alert(1)</script>` **renders as text** (auto-escaped)
- [ ] Ping `8.8.8.8; cat /etc/passwd` **returns error** (no shell=True)
- [ ] Upload `../../etc/passwd` **blocked** (sanitized filename)
- [ ] Access another user's note **denied** (ownership check)
- [ ] Session **expires** (secure cookie config)
- [ ] CSP header **present** in response
- [ ] Rate limiting **active** on login endpoints

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

> **The vulnerable `app_vulnerable.py` is for EDUCATIONAL PURPOSES ONLY.**
>
> - Contains: SQLi, XSS, RCE, Path Traversal, IDOR, Insecure Deserialization
> - **NEVER** deploy to production, staging, or any network-accessible environment
> - Run only on **localhost** in an isolated VM/container
> - Delete `app.db` after testing — it contains plaintext passwords

---

## ✅ Submission Deliverables

- [ ] Vulnerable app (`app_vulnerable.py`) — pushed to GitHub
- [ ] Secure app (`app_secure.py`) — pushed to GitHub
- [ ] Audit report (`AUDIT_REPORT.md`) — 10 findings documented
- [ ] LinkedIn post with screenshots/video
- [ ] CodeAlpha submission form completed

---

## 🔗 Navigation

← **Task 02** [`../02_phishing_awareness_module/README.md`](../02_phishing_awareness_module/README.md) | **Master README** [`../README.md`](../README.md) | **Task 04 →** [`../04_network_ids/README.md`](../04_network_ids/README.md)