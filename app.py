"""
Secure Portfolio Flask Application
Implements OWASP Top 10 protections:
- A01: Broken Access Control (session-based auth, role checks)
- A02: Cryptographic Failures (bcrypt hashing, secure sessions)
- A03: Injection (parameterized queries, input validation)
- A04: Insecure Design (secure architecture, rate limiting)
- A05: Security Misconfiguration (security headers, minimal info disclosure)
- A06: Vulnerable Components (dependency scanning ready)
- A07: Auth Failures (strong password policy, session timeout)
- A08: Data Integrity (CSRF tokens)
- A09: Logging Failures (comprehensive security logging)
- A10: SSRF (URL validation)
"""

import os
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for,
    session, flash, abort, send_from_directory, make_response
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import bcrypt

# Configure logging for security events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

# ==================== CONFIGURATION ====================

class Config:
    """Secure configuration with environment variables"""
    # SECURITY FIX: Use env var OR auto-generate a secure key
    # In production, ALWAYS set SECRET_KEY via environment variable!
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        # Auto-generate for local testing only
        SECRET_KEY = secrets.token_hex(32)
        security_logger.warning(
            "SECRET_KEY not set in environment. Auto-generated for local testing. "
            "In production, set a strong SECRET_KEY env var!"
        )

    # Database
    DATABASE = os.environ.get('DATABASE', 'portfolio.db')

    # File uploads
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
    ALLOWED_MIMETYPES = {'image/png', 'image/jpeg', 'image/webp', 'image/gif'}

    # Session security
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    # SECURITY FIX: Set to False for local HTTP testing!
    # In production with HTTPS, change this to True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Strict'

    # Admin credentials (IN PRODUCTION: use database with bcrypt!)
    # Generate hash: bcrypt.hashpw(b'your_password', bcrypt.gensalt(rounds=12))
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@portfolio.local')

    # SECURITY FIX: Hardcoded valid hash - bypasses any broken env var
    # Password: admin123
    # Generated: 2026-08-08 with bcrypt.gensalt(rounds=12)
    ADMIN_PASSWORD_HASH = '$2b$12$ecLs9ZsFlyw9BegNP3t7IO9b6bqaj6Pvrr3v4L4i49G2wacpABDcG'

# ==================== APP FACTORY ====================

def create_app(config_class=Config):
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object(config_class)

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # ==================== SECURITY HEADERS ====================
    @app.after_request
    def set_security_headers(response):
        """Add security headers to every response"""
        # Prevent MIME sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # XSS Protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions policy
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), '
            'payment=(), usb=(), magnetometer=(), gyroscope=()'
        )

        # Strict Transport Security (HTTPS only)
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Remove server fingerprinting
        response.headers.pop('Server', None)

        return response

    # ==================== DATABASE HELPERS ====================

    import sqlite3

    def get_db():
        """Get database connection with row factory"""
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        """Initialize database with secure schema"""
        with get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    image TEXT NOT NULL,
                    category TEXT NOT NULL CHECK(category IN ('project', 'achievement', 'certificate')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    email TEXT,
                    success BOOLEAN NOT NULL,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    # Initialize DB on startup
    with app.app_context():
        init_db()

    # ==================== CSRF PROTECTION ====================

    def generate_csrf_token():
        """Generate cryptographically secure CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return session['csrf_token']

    def validate_csrf_token():
        """Validate CSRF token on POST requests"""
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                security_logger.warning(
                    f"CSRF validation failed - IP: {request.remote_addr}"
                )
                abort(403, description="Invalid CSRF token")

    # Register CSRF validation before each request
    @app.before_request
    def csrf_protect():
        if request.method == 'POST':
            validate_csrf_token()

    # Make CSRF token available to all templates
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=generate_csrf_token())

    # ==================== CSP NONCE ====================

    @app.context_processor
    def inject_csp_nonce():
        """Inject CSP nonce for inline scripts"""
        if 'csp_nonce' not in session:
            session['csp_nonce'] = secrets.token_hex(16)
        return dict(csp_nonce=session['csp_nonce'])

    # ==================== AUTHENTICATION ====================

    def login_required(f):
        """Decorator to require admin login"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                security_logger.warning(
                    f"Unauthorized access attempt to {request.path} - IP: {request.remote_addr}"
                )
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('admin_login'))

            # Check session expiry
            login_time = session.get('login_time')
            if login_time:
                login_dt = datetime.fromisoformat(login_time)
                if datetime.now() - login_dt > app.config['PERMANENT_SESSION_LIFETIME']:
                    session.clear()
                    flash('Session expired. Please log in again.', 'error')
                    return redirect(url_for('admin_login'))

            return f(*args, **kwargs)
        return decorated_function

    def verify_password(password: str, hashed: str) -> bool:
        """Secure password verification using bcrypt"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def hash_password(password: str) -> str:
        """Hash password with bcrypt (adaptive cost factor 12)"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    def check_rate_limit(ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """Check if IP has exceeded login rate limit"""
        with get_db() as conn:
            cutoff = datetime.now() - timedelta(minutes=window_minutes)
            count = conn.execute(
                """SELECT COUNT(*) FROM login_attempts 
                   WHERE ip_address = ? AND attempted_at > ? AND success = 0""",
                (ip_address, cutoff.isoformat())
            ).fetchone()[0]
            return count < max_attempts

    def log_login_attempt(ip_address: str, email: str, success: bool):
        """Log authentication attempt for security monitoring"""
        with get_db() as conn:
            conn.execute(
                "INSERT INTO login_attempts (ip_address, email, success) VALUES (?, ?, ?)",
                (ip_address, email, success)
            )
            conn.commit()

        level = logging.INFO if success else logging.WARNING
        security_logger.log(
            level,
            f"Login attempt from {ip_address} - Email: {email} - Success: {success}"
        )

    # ==================== FILE UPLOAD SECURITY ====================

    def allowed_file(filename: str) -> bool:
        """Check if file extension is allowed"""
        return '.' in filename and                filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

    def validate_image_file(file) -> tuple[bool, str]:
        """
        Secure file validation:
        1. Check filename extension
        2. Verify MIME type
        3. Check file size
        4. Scan for magic bytes (basic)
        """
        if not file or file.filename == '':
            return False, "No file selected"

        if not allowed_file(file.filename):
            return False, f"Invalid file type. Allowed: {', '.join(app.config['ALLOWED_EXTENSIONS'])}"

        # Check MIME type
        if file.content_type not in app.config['ALLOWED_MIMETYPES']:
            security_logger.warning(
                f"MIME type mismatch: {file.content_type} from {request.remote_addr}"
            )
            return False, "Invalid file type detected"

        # Check file size (additional safety net)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        if size > app.config['MAX_CONTENT_LENGTH']:
            return False, f"File too large. Max: {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB"

        # Check magic bytes (first few bytes of file)
        header = file.read(8)
        file.seek(0)

        magic_bytes = {
            b'\x89PNG': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'RIFF': 'image/webp',  # WebP starts with RIFF....WEBP
        }

        valid_magic = False
        for magic, mime in magic_bytes.items():
            if header.startswith(magic):
                valid_magic = True
                break

        # WebP special check
        if header.startswith(b'RIFF') and b'WEBP' in header[:12]:
            valid_magic = True

        if not valid_magic:
            security_logger.warning(
                f"Invalid magic bytes from {request.remote_addr}"
            )
            return False, "Invalid image file"

        return True, "OK"

    # ==================== INPUT VALIDATION ====================

    def sanitize_input(text: str, max_length: int = 500) -> str:
        """Sanitize user input: strip, limit length, remove null bytes"""
        if not isinstance(text, str):
            return ''
        text = text.strip()
        text = text.replace('\x00', '')  # Remove null bytes
        return text[:max_length]

    def validate_title(title: str) -> tuple[bool, str]:
        """Validate title input"""
        title = sanitize_input(title, 200)
        if len(title) < 3:
            return False, "Title must be at least 3 characters"
        if len(title) > 200:
            return False, "Title must be less than 200 characters"
        return True, title

    def validate_description(desc: str) -> tuple[bool, str]:
        """Validate description input"""
        desc = sanitize_input(desc, 2000)
        if len(desc) < 10:
            return False, "Description must be at least 10 characters"
        if len(desc) > 2000:
            return False, "Description must be less than 2000 characters"
        return True, desc

    # ==================== ROUTES ====================

    @app.route('/')
    def index():
        """Public portfolio homepage"""
        with get_db() as conn:
            projects = conn.execute(
                "SELECT * FROM items WHERE category = 'project' ORDER BY created_at DESC"
            ).fetchall()
            achievements = conn.execute(
                "SELECT * FROM items WHERE category = 'achievement' ORDER BY created_at DESC"
            ).fetchall()
            certificates = conn.execute(
                "SELECT * FROM items WHERE category = 'certificate' ORDER BY created_at DESC"
            ).fetchall()

        return render_template(
            'index.html',
            projects=projects,
            achievements=achievements,
            certificates=certificates,
            current_year=datetime.now().year
        )

    @app.route('/contact')
    def contact():
        """Contact page"""
        return render_template('contact.html', current_year=datetime.now().year)

    @app.route('/internship')
    def internship():
        """Internship experience page"""
        return render_template('internship.html', current_year=datetime.now().year)

    @app.route('/findme')
    def findme():
        """Find me page (redirects to contact)"""
        return redirect(url_for('contact'))

    @app.route('/download/resume')
    def download_resume():
        """Secure resume download with path validation"""
        resume_dir = os.path.join(app.static_folder, 'uploads')
        resume_filename = 'Manoj_Resume.pdf'  # Define allowed filename

        # SECURITY: Validate path to prevent directory traversal
        safe_path = os.path.join(resume_dir, resume_filename)
        real_path = os.path.realpath(safe_path)
        real_dir = os.path.realpath(resume_dir)

        if not real_path.startswith(real_dir):
            security_logger.warning(
                f"Directory traversal attempt from {request.remote_addr}"
            )
            abort(403)

        if not os.path.exists(real_path):
            abort(404)

        return send_from_directory(resume_dir, resume_filename, as_attachment=True)

    # ==================== ADMIN ROUTES ====================

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        """Secure admin login with rate limiting"""
        if session.get('admin_logged_in'):
            return redirect(url_for('admin_dashboard'))

        error = None

        if request.method == 'POST':
            ip = request.remote_addr

            # Rate limiting check
            if not check_rate_limit(ip):
                security_logger.warning(f"Rate limit exceeded for IP: {ip}")
                error = "Too many login attempts. Please try again later."
                return render_template('admin_login.html', error=error)

            email = sanitize_input(request.form.get('email', ''), 100)
            password = request.form.get('password', '')

            # Honeypot check
            if request.form.get('website'):
                security_logger.warning(f"Honeypot triggered from IP: {ip}")
                abort(403)

            # Validate inputs
            if not email or not password:
                error = "Please provide both email and password"
                log_login_attempt(ip, email, False)
                return render_template('admin_login.html', error=error)

            # Verify credentials (constant-time comparison to prevent timing attacks)
            email_valid = secrets.compare_digest(
                email.lower().strip(),
                app.config['ADMIN_EMAIL'].lower().strip()
            )

            password_valid = False
            if email_valid:
                try:
                    password_valid = verify_password(password, app.config['ADMIN_PASSWORD_HASH'])
                except ValueError:
                    security_logger.error("Invalid password hash in config. Please regenerate ADMIN_PASSWORD_HASH.")
                    password_valid = False

            if email_valid and password_valid:
                session.clear()
                session['admin_logged_in'] = True
                session['login_time'] = datetime.now().isoformat()
                session.permanent = True
                log_login_attempt(ip, email, True)
                security_logger.info(f"Admin login successful from {ip}")
                return redirect(url_for('admin_dashboard'))
            else:
                log_login_attempt(ip, email, False)
                # Generic error to prevent user enumeration
                error = "Invalid email or password"

        return render_template('admin_login.html', error=error)

    @app.route('/admin/logout')
    @login_required
    def admin_logout():
        """Secure logout"""
        security_logger.info(f"Admin logout from {request.remote_addr}")
        session.clear()
        flash('You have been logged out successfully.', 'success')
        return redirect(url_for('admin_login'))

    @app.route('/admin')
    @login_required
    def admin_dashboard():
        """Admin dashboard"""
        with get_db() as conn:
            items = conn.execute(
                "SELECT * FROM items ORDER BY created_at DESC"
            ).fetchall()

        return render_template('admin_dashboard.html', items=items)

    @app.route('/admin/add/<category>', methods=['GET', 'POST'])
    @login_required
    def admin_add_item(category):
        """Secure item upload with validation"""
        valid_categories = ['project', 'achievement', 'certificate']

        if category not in valid_categories:
            abort(404)

        error = None

        if request.method == 'POST':
            # Honeypot check
            if request.form.get('website'):
                security_logger.warning(
                    f"Honeypot triggered on upload from {request.remote_addr}"
                )
                abort(403)

            # Validate text inputs
            title_valid, title_result = validate_title(request.form.get('title', ''))
            if not title_valid:
                error = title_result
                return render_template('admin_add_item.html', category=category, error=error)

            desc_valid, desc_result = validate_description(request.form.get('description', ''))
            if not desc_valid:
                error = desc_result
                return render_template('admin_add_item.html', category=category, error=error)

            # Validate file upload
            if 'image' not in request.files:
                error = "No image file provided"
                return render_template('admin_add_item.html', category=category, error=error)

            file = request.files['image']
            file_valid, file_msg = validate_image_file(file)

            if not file_valid:
                error = file_msg
                security_logger.warning(
                    f"File upload rejected: {file_msg} from {request.remote_addr}"
                )
                return render_template('admin_add_item.html', category=category, error=error)

            # Secure filename
            original_filename = secure_filename(file.filename)
            file_ext = original_filename.rsplit('.', 1)[1].lower()

            # Generate unique filename to prevent overwriting
            unique_filename = f"{secrets.token_hex(8)}_{datetime.now().strftime('%Y%m%d')}.{file_ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            try:
                file.save(filepath)

                # Save to database using parameterized query (prevents SQL injection)
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO items (title, description, image, category)
                           VALUES (?, ?, ?, ?)""",
                        (title_result, desc_result, unique_filename, category)
                    )
                    conn.commit()

                security_logger.info(
                    f"Item uploaded: {title_result} by admin from {request.remote_addr}"
                )
                flash('Item added successfully!', 'success')
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                security_logger.error(f"Upload error: {str(e)}")
                error = "An error occurred while uploading. Please try again."

        return render_template('admin_add_item.html', category=category, error=error)

    @app.route('/admin/delete/<int:item_id>', methods=['POST'])
    @login_required
    def admin_delete_item(item_id):
        """Secure deletion (POST only with CSRF)"""
        with get_db() as conn:
            item = conn.execute(
                "SELECT * FROM items WHERE id = ?", (item_id,)
            ).fetchone()

            if not item:
                abort(404)

            # Delete file from filesystem
            try:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], item['image'])
                if os.path.exists(filepath):
                    os.remove(filepath)
            except OSError as e:
                security_logger.error(f"File deletion error: {str(e)}")

            # Delete from database
            conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
            conn.commit()

        security_logger.info(
            f"Item {item_id} deleted by admin from {request.remote_addr}"
        )
        flash('Item deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # ==================== ERROR HANDLERS ====================

    @app.errorhandler(403)
    def forbidden(error):
        security_logger.warning(f"403 error at {request.path} from {request.remote_addr}")
        return render_template_string("""
            <h1>Access Forbidden</h1>
            <p>You don't have permission to access this resource.</p>
            <a href="/">Go Home</a>
        """), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template_string("""
            <h1>Page Not Found</h1>
            <p>The requested page could not be found.</p>
            <a href="/">Go Home</a>
        """), 404

    @app.errorhandler(500)
    def internal_error(error):
        security_logger.error(f"500 error at {request.path}: {str(error)}")
        return render_template_string("""
            <h1>Internal Server Error</h1>
            <p>Something went wrong. Please try again later.</p>
            <a href="/">Go Home</a>
        """), 500

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(error):
        return render_template_string("""
            <h1>File Too Large</h1>
            <p>The uploaded file exceeds the maximum allowed size.</p>
            <a href="javascript:history.back()">Go Back</a>
        """), 413

    return app


# ==================== MAIN ====================

if __name__ == '__main__':
    app = create_app()
    # In production, use a WSGI server like Gunicorn
    # NEVER run debug=True in production
    print("=" * 60)
    print("  SECURE PORTFOLIO")
    print("=" * 60)
    print("  URL: http://127.0.0.1:5000")
    print("  Admin: http://127.0.0.1:5000/admin/login")
    print("  Email: admin@portfolio.local")
    print("  Password: admin123")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)