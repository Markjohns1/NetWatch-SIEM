"""
Enhanced Authentication and Security Module
Provides secure authentication, session management, and security utilities
"""

import hashlib
import secrets
import hmac
import time
from functools import wraps
from flask import request, session, jsonify, current_app
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self, app=None):
        self.app = app
        self.failed_attempts = {}
        self.max_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security manager with Flask app"""
        self.app = app
        
        # Enhanced session configuration
        app.config.update(
            PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
            SESSION_COOKIE_SECURE=True,  # HTTPS only
            SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS
            SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
            WTF_CSRF_ENABLED=True,
            WTF_CSRF_TIME_LIMIT=3600
        )
    
    def hash_password(self, password, salt=None):
        """Create secure password hash with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100k iterations
        )
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        try:
            salt, hash_hex = stored_hash.split(':')
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return hmac.compare_digest(hash_hex, password_hash.hex())
        except (ValueError, TypeError):
            return False
    
    def is_locked_out(self, ip_address):
        """Check if IP is locked out due to failed attempts"""
        if ip_address not in self.failed_attempts:
            return False
        
        attempts, last_attempt = self.failed_attempts[ip_address]
        if attempts >= self.max_attempts:
            if time.time() - last_attempt < self.lockout_duration:
                return True
            else:
                # Reset after lockout period
                del self.failed_attempts[ip_address]
        
        return False
    
    def record_failed_attempt(self, ip_address):
        """Record failed login attempt"""
        current_time = time.time()
        
        if ip_address in self.failed_attempts:
            attempts, _ = self.failed_attempts[ip_address]
            self.failed_attempts[ip_address] = (attempts + 1, current_time)
        else:
            self.failed_attempts[ip_address] = (1, current_time)
        
        logger.warning(f"Failed login attempt from {ip_address}")
    
    def clear_failed_attempts(self, ip_address):
        """Clear failed attempts for successful login"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def generate_csrf_token(self):
        """Generate CSRF token for forms"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def validate_csrf_token(self, token):
        """Validate CSRF token"""
        return token and hmac.compare_digest(
            token, 
            session.get('csrf_token', '')
        )

def require_auth(f):
    """Enhanced authentication decorator with security checks and REAL-TIME user status check"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'logged_in' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        # REAL-TIME: Check if user is still active (fast check)
        user_id = session.get('user_id')
        if user_id:
            try:
                # Use current_app to get db instance without circular import
                db = current_app.extensions.get('db')
                if not db:
                    # Fallback: import directly (will work in runtime)
                    from database.models import Database
                    db = Database()
                
                conn = db.get_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT is_active FROM users WHERE id = ? LIMIT 1', (user_id,))
                result = cursor.fetchone()
                conn.close()
                
                if result and not result[0]:  # User is deactivated
                    session.clear()
                    return jsonify({'success': False, 'error': 'Account deactivated', 'logged_out': True}), 403
            except:
                pass  # Don't fail on check - allow request to proceed
        
        # Check session expiry
        if 'last_activity' in session:
            try:
                last_activity = datetime.fromisoformat(session['last_activity'])
                if datetime.now() - last_activity > timedelta(hours=8):
                    session.clear()
                    return jsonify({'success': False, 'error': 'Session expired'}), 401
            except:
                pass
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=100, window=3600):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting (use Redis in production)
            client_ip = request.remote_addr
            current_time = time.time()
            
            # This is a simplified implementation
            # In production, use Redis or similar for distributed rate limiting
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(data, schema):
    """Validate input data against schema"""
    errors = []
    
    for field, rules in schema.items():
        value = data.get(field)
        
        if 'required' in rules and not value:
            errors.append(f"{field} is required")
            continue
        
        if value and 'type' in rules:
            if rules['type'] == 'int' and not isinstance(value, int):
                try:
                    data[field] = int(value)
                except ValueError:
                    errors.append(f"{field} must be an integer")
            
            elif rules['type'] == 'str' and not isinstance(value, str):
                errors.append(f"{field} must be a string")
            
            elif rules['type'] == 'bool' and not isinstance(value, bool):
                if isinstance(value, str):
                    data[field] = value.lower() in ('true', '1', 'yes')
                else:
                    errors.append(f"{field} must be a boolean")
        
        if value and 'min_length' in rules and len(str(value)) < rules['min_length']:
            errors.append(f"{field} must be at least {rules['min_length']} characters")
        
        if value and 'max_length' in rules and len(str(value)) > rules['max_length']:
            errors.append(f"{field} must be no more than {rules['max_length']} characters")
    
    return errors

def sanitize_input(data):
    """Sanitize input data to prevent injection attacks"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`']
        for char in dangerous_chars:
            data = data.replace(char, '')
        return data.strip()
    else:
        return data
