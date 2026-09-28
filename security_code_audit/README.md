# Security Code Audit Project

A comprehensive security audit of a vulnerable Flask application, demonstrating 27 security vulnerabilities across OWASP Top 10 categories, with complete remediation.

## Project Structure

```
security_code_audit/
├── app.py              # Vulnerable application (FOR TRAINING ONLY)
├── app_secure.py       # Fully remediated secure version
├── SECURITY_AUDIT_REPORT.md  # Complete audit report (27 findings)
├── AUDIT_TOOLKIT.md    # Tool commands & remediation code examples
└── README.md           # This file
```

## Vulnerabilities Covered

| Category | Count | Severity |
|----------|-------|----------|
| SQL Injection | 6 | Critical |
| Cross-Site Scripting (XSS) | 4 | Critical |
| Command Injection | 2 | Critical |
| Insecure Deserialization | 2 | Critical |
| XXE | 1 | High |
| SSRF | 2 | High |
| Path Traversal | 2 | High |
| CSRF | 3 | High |
| IDOR / Broken Access Control | 4 | High |
| Broken Authentication | 5 | High |
| Sensitive Data Exposure | 4 | High |
| Security Misconfiguration | 3 | Medium |
| Insecure File Upload | 2 | High |
| Race Condition | 1 | Medium |
| Insufficient Logging | 1 | Low |
| **Total** | **27** | |

## Quick Start

### Run Vulnerable App (Training Only)
```bash
cd security_code_audit
python app.py
# Runs on http://localhost:5000
```

### Run Secure Version
```bash
cd security_code_audit
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app_secure.py
```

### Run Security Scans
```bash
# Install tools
pip install bandit semgrep safety pip-audit

# Run all scans
bandit -r app.py -f json -o bandit-report.json
semgrep --config=auto app.py --json=semgrep-report.json
safety check --json
pip-audit --format=json
```

## Key Vulnerabilities Demonstrated

### 1. SQL Injection (6 instances)
```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"

# SECURE (app_secure.py)
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### 2. XSS (4 instances)
```python
# VULNERABLE
{{ content | safe }}

# SECURE
{{ content }}  # Auto-escaped
```

### 3. Command Injection (2 instances)
```python
# VULNERABLE
subprocess.run(f"ping {host}", shell=True)

# SECURE
subprocess.run(['ping', '-c', '4', host], capture_output=True)
```

### 4. Insecure Deserialization (2 instances)
```python
# VULNERABLE
pickle.loads(user_data)

# SECURE
json.loads(user_data)
```

### 5. Path Traversal (2 instances)
```python
# VULNERABLE
filepath = os.path.join('/uploads', filename)

# SECURE
filename = secure_filename(filename)
filepath = os.path.join(UPLOAD_FOLDER, filename)
if not filepath.startswith(os.path.abspath(UPLOAD_FOLDER)):
    raise ValueError("Path traversal")
```

## Security Tools Quick Reference

| Tool | Install | Command |
|------|---------|---------|
| Bandit | `pip install bandit` | `bandit -r app.py` |
| Semgrep | `pip install semgrep` | `semgrep --config=auto app.py` |
| Safety | `pip install safety` | `safety check --json` |
| pip-audit | `pip install pip-audit` | `pip-audit --format=json` |
| Trivy | See docs | `trivy fs .` |

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
- run: pip install bandit semgrep safety pip-audit
- run: bandit -r . -f json -o bandit-report.json || true
- run: semgrep --config=auto . --json=semgrep-report.json || true
- run: safety check --json --output safety-report.json || true
```

## Remediation Priority

| Priority | Issues | Timeline |
|----------|--------|----------|
| P0 - Critical | SQLi, RCE, XXE, SSRF, Deserialization | 24-48 hours |
| P1 - High | XSS, CSRF, IDOR, Path Traversal | 1 week |
| P2 - Medium | Auth, Data Exposure, Race Conditions | 2 weeks |
| P3 - Low | Headers, Logging | 1 month |

## Learning Objectives

This project teaches:
- ✅ Identifying OWASP Top 10 vulnerabilities in code
- ✅ Using static analysis tools (SAST)
- ✅ Manual code review techniques
- ✅ Secure coding patterns
- ✅ Remediation strategies
- ✅ CI/CD security integration

## ⚠️ WARNING

**The vulnerable `app.py` contains intentional security flaws for educational purposes. NEVER deploy it in production or expose it to untrusted networks.**

Use only in isolated lab environments for security training.

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/stable/security/)
- [Python Security Guide](https://python-security.readthedocs.io/)