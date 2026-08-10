# 🔒 Secure Portfolio — Security Implementation Guide

## Overview
This portfolio has been secured against the OWASP Top 10 vulnerabilities. Below is a comprehensive breakdown of every security measure implemented.

---

## 📁 File Structure

```
secure_portfolio/
├── app.py                  # Secure Flask backend
├── requirements.txt        # Dependencies
├── security.log           # Security event logs
├── templates/
│   ├── base.html          # Base template with CSP, security headers
│   ├── index.html         # Main portfolio
│   ├── contact.html       # Contact page
│   ├── internship.html    # Internship page
│   ├── admin_login.html   # Secure login
│   ├── admin_dashboard.html
│   └── admin_add_item.html
└── static/
    ├── css/
    │   └── style.css      # Secure, consistent styles
    └── js/
        └── main.js        # XSS-safe JavaScript
```

---

## 🛡️ OWASP Top 10 Mitigations

### A01: Broken Access Control ✅
- **Session-based authentication** with timeout (2 hours)
- **`@login_required` decorator** on all admin routes
- **Role-based access** — only admins can access `/admin/*`
- **Secure logout** clears session completely
- **POST-only deletion** — delete requires POST + CSRF token

```python
# Before: Anyone could access /admin/delete/1 via GET
@app.route('/admin/delete/<id>')  # ❌ VULNERABLE

# After: Requires POST + auth + CSRF
@app.route('/admin/delete/<int:item_id>', methods=['POST'])  # ✅ SECURE
@login_required
def admin_delete_item(item_id):
```

### A02: Cryptographic Failures ✅
- **bcrypt password hashing** with adaptive cost factor 12
- **32+ character SECRET_KEY** from environment variable
- **Secure session cookies**: HttpOnly, Secure, SameSite=Strict
- **HTTPS enforcement** via HSTS header in production

```bash
# Generate secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Set environment variables
export SECRET_KEY="your-64-char-hex-key-here"
export ADMIN_EMAIL="admin@yourdomain.com"
export ADMIN_PASSWORD_HASH="$2b$12$..."  # bcrypt hash
```

### A03: Injection ✅
- **Parameterized SQL queries** — never string interpolation
- **Input sanitization** — strip null bytes, limit length
- **Filename sanitization** with `secure_filename()`

```python
# Before: SQL Injection possible
query = f"SELECT * FROM items WHERE id = {item_id}"  # ❌

# After: Parameterized query
cursor.execute("SELECT * FROM items WHERE id = ?", (item_id,))  # ✅
```

### A04: Insecure Design ✅
- **Rate limiting** on login (5 attempts per 15 minutes per IP)
- **Honeypot fields** in forms (anti-bot)
- **File type validation** — extension + MIME type + magic bytes
- **File size limits** — 5MB max
- **Unique filenames** — prevents overwriting

### A05: Security Misconfiguration ✅
- **Security headers** on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Strict-Transport-Security` (HSTS)
  - `Permissions-Policy`
- **Server fingerprinting removed**
- **Generic error messages** to users, detailed logs to server
- **No debug mode in production**

### A06: Vulnerable Components ✅
- **Pinned dependency versions** in requirements.txt
- Ready for automated scanning with:
  ```bash
  pip install safety
  safety check -r requirements.txt
  ```

### A07: Authentication Failures ✅
- **bcrypt adaptive hashing** (slow by design)
- **Session timeout** after 2 hours
- **Rate limiting** prevents brute force
- **Generic error messages** ("Invalid email or password")
- **Constant-time comparison** prevents timing attacks
- **Login attempt logging** for monitoring

```python
# Constant-time comparison prevents user enumeration
email_valid = secrets.compare_digest(
    email.lower().strip(),
    app.config['ADMIN_EMAIL'].lower().strip()
)
```

### A08: Data Integrity Failures ✅
- **CSRF tokens** on all state-changing forms
- **Cryptographically secure token generation** with `secrets.token_urlsafe()`
- **Token validation** on every POST request

```html
<!-- Every form includes CSRF token -->
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

### A09: Security Logging Failures ✅
- **Comprehensive security logging** to `security.log`
- Events logged:
  - Login attempts (success/failure)
  - Logouts
  - CSRF failures
  - File upload rejections
  - Rate limit triggers
  - Unauthorized access attempts
  - Honeypot triggers

```python
security_logger.warning(
    f"CSRF validation failed - IP: {request.remote_addr}"
)
```

### A10: Server-Side Request Forgery (SSRF) ✅
- **Path validation** on file downloads
- **Real path verification** prevents directory traversal
- **Allowed filename whitelist** for resume downloads

```python
# Prevent directory traversal
real_path = os.path.realpath(safe_path)
real_dir = os.path.realpath(resume_dir)
if not real_path.startswith(real_dir):
    abort(403)
```

---

## 🎨 Design Improvements

### Consistent Design System
- **Glass morphism** cards with backdrop blur
- **Cyan accent color** with glow effects
- **Dark/light theme** with system preference detection
- **Smooth animations** via IntersectionObserver (performance-safe)
- **Fully responsive** mobile-first design

### Accessibility (A11y)
- **ARIA labels** on all interactive elements
- **Focus management** in modal with focus trap
- **Keyboard navigation** support (Escape to close modal)
- **Focus-visible** styles for keyboard users
- **Semantic HTML** (article, section, nav, main)
- **Alt text** on all images

### Performance
- **Lazy loading** on images
- **IntersectionObserver** instead of scroll events
- **Throttled** scroll handlers
- **CSS transitions** instead of JS animations where possible

---

## 🚀 Deployment Checklist

Before deploying to production:

- [ ] Set `SECRET_KEY` environment variable (64+ hex chars)
- [ ] Set `ADMIN_EMAIL` and `ADMIN_PASSWORD_HASH` env vars
- [ ] Change default admin password hash (generate with bcrypt)
- [ ] Set `SESSION_COOKIE_SECURE = True` (requires HTTPS)
- [ ] Use HTTPS with valid SSL certificate
- [ ] Set `debug=False` in app.run()
- [ ] Use WSGI server (Gunicorn/uWSGI) instead of Flask dev server
- [ ] Configure firewall (only ports 80/443 open)
- [ ] Set up fail2ban for brute force protection
- [ ] Regular dependency updates: `pip install --upgrade -r requirements.txt`
- [ ] Enable automated security scanning in CI/CD

---

## 🔧 Setup Instructions

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_EMAIL="your-email@example.com"
export ADMIN_PASSWORD_HASH="$(python -c 'import bcrypt; print(bcrypt.hashpw(b"your-password", bcrypt.gensalt(rounds=12)).decode())')"

# 3. Create upload directory
mkdir -p static/uploads

# 4. Add your profile image
# Place profile.jpg in static/

# 5. Run the application
python app.py
```

---

## 📝 Additional Security Recommendations

1. **Use a reverse proxy** (Nginx/Apache) in front of Flask
2. **Enable WAF** (Web Application Firewall) like ModSecurity
3. **Set up monitoring** with tools like Snyk or Dependabot
4. **Regular backups** of the database
5. **Use environment-specific configs** (dev/staging/prod)
6. **Implement Content Security Policy reporting** with report-uri
7. **Add CAPTCHA** on login after 3 failed attempts
8. **Use a secrets manager** (AWS Secrets Manager, HashiCorp Vault) instead of env vars
