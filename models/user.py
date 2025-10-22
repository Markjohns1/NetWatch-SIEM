"""
User Management Model for NetWatch SIEM
Handles user registration, authentication, and role management
"""

import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import sqlite3
import json

class UserManager:
    def __init__(self, db):
        self.db = db
        self.init_user_tables()
    
    def init_user_tables(self):
        """Initialize user-related database tables"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                is_verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                two_factor_enabled INTEGER DEFAULT 0,
                two_factor_secret TEXT,
                preferences TEXT,
                metadata TEXT
            )
        ''')
        
        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # User roles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                permissions TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # User activity log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create default roles
        self._create_default_roles(cursor)
        
        # Create default admin user if none exists
        self._create_default_admin(cursor)
        
        conn.commit()
        conn.close()
    
    def _create_default_roles(self, cursor):
        """Create default user roles"""
        default_roles = [
            ('admin', '["all"]', 'Full system access'),
            ('operator', '["view_devices", "view_alerts", "manage_alerts", "view_logs"]', 'Network operations'),
            ('viewer', '["view_devices", "view_alerts", "view_logs"]', 'Read-only access'),
            ('analyst', '["view_devices", "view_alerts", "view_logs", "view_analytics", "manage_rules"]', 'Security analysis')
        ]
        
        for role_name, permissions, description in default_roles:
            cursor.execute('''
                INSERT OR IGNORE INTO user_roles (name, permissions, description)
                VALUES (?, ?, ?)
            ''', (role_name, permissions, description))
    
    def _create_default_admin(self, cursor):
        """Create default admin user if none exists"""
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            username = 'admin'
            email = 'admin@netwatch.local'
            password = 'NetWatch2024!'  # Should be changed on first login
            
            salt = secrets.token_hex(32)
            password_hash = self._hash_password(password, salt)
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, is_active, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, 'admin', 1, 1))
    
    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100k iterations
        )
        return f"{salt}:{password_hash.hex()}", salt
    
    def _verify_password(self, password: str, stored_hash: str) -> bool:
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
    
    def register_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict:
        """Register a new user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Validate input
            if not username or len(username) < 3:
                return {'success': False, 'error': 'Username must be at least 3 characters'}
            
            if not email or '@' not in email:
                return {'success': False, 'error': 'Valid email address required'}
            
            if not password or len(password) < 8:
                return {'success': False, 'error': 'Password must be at least 8 characters'}
            
            # Check if username or email already exists
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                return {'success': False, 'error': 'Username or email already exists'}
            
            # Hash password
            password_hash, salt = self._hash_password(password)
            
            # Insert user
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, is_active, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, role, 1, 0))
            
            user_id = cursor.lastrowid
            
            # Log registration
            self._log_user_activity(user_id, 'user_registered', {
                'username': username,
                'email': email,
                'role': role
            })
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'user_id': user_id, 'message': 'User registered successfully'}
            
        except sqlite3.IntegrityError:
            conn.rollback()
            conn.close()
            return {'success': False, 'error': 'Username or email already exists'}
        except Exception as e:
            conn.rollback()
            conn.close()
            return {'success': False, 'error': str(e)}
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Dict:
        """Authenticate user login"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Get user by username or email
            cursor.execute('''
                SELECT id, username, email, password_hash, role, is_active, is_verified,
                       login_attempts, locked_until
                FROM users 
                WHERE (username = ? OR email = ?) AND is_active = 1
            ''', (username, username))
            
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'error': 'Invalid credentials'}
            
            user_id, db_username, email, password_hash, role, is_active, is_verified, login_attempts, locked_until = user
            
            # Check if account is locked
            if locked_until:
                locked_until_dt = datetime.fromisoformat(locked_until)
                if datetime.now() < locked_until_dt:
                    return {'success': False, 'error': 'Account is temporarily locked'}
            
            # Verify password
            if not self._verify_password(password, password_hash):
                # Increment failed login attempts
                new_attempts = login_attempts + 1
                if new_attempts >= 5:
                    # Lock account for 30 minutes
                    locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                    cursor.execute('''
                        UPDATE users SET login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (new_attempts, locked_until, user_id))
                else:
                    cursor.execute('''
                        UPDATE users SET login_attempts = ?
                        WHERE id = ?
                    ''', (new_attempts, user_id))
                
                conn.commit()
                conn.close()
                
                # Log failed login
                self._log_user_activity(user_id, 'login_failed', {
                    'username': username,
                    'ip_address': ip_address,
                    'attempts': new_attempts
                })
                
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Successful login - reset attempts and update last login
            cursor.execute('''
                UPDATE users 
                SET login_attempts = 0, locked_until = NULL, last_login = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            
            conn.commit()
            conn.close()
            
            # Log successful login
            self._log_user_activity(user_id, 'login_success', {
                'username': username,
                'ip_address': ip_address
            })
            
            return {
                'success': True,
                'user': {
                    'id': user_id,
                    'username': db_username,
                    'email': email,
                    'role': role,
                    'is_verified': bool(is_verified)
                }
            }
            
        except Exception as e:
            conn.rollback()
            conn.close()
            return {'success': False, 'error': str(e)}
    
    def create_session(self, user_id: int, ip_address: str = None, user_agent: str = None) -> str:
        """Create a new user session"""
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=8)
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, session_token, ip_address, user_agent, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate session token and return user info"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.role, u.is_verified, s.expires_at
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = ? AND s.is_active = 1 AND u.is_active = 1
        ''', (session_token,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        user_id, username, email, role, is_verified, expires_at = result
        
        # Check if session is expired
        if datetime.now() > datetime.fromisoformat(expires_at):
            self.invalidate_session(session_token)
            return None
        
        return {
            'id': user_id,
            'username': username,
            'email': email,
            'role': role,
            'is_verified': bool(is_verified)
        }
    
    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE user_sessions SET is_active = 0 WHERE session_token = ?
        ''', (session_token,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected > 0
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, role, is_active, is_verified, created_at, last_login
            FROM users WHERE id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        return {
            'id': result[0],
            'username': result[1],
            'email': result[2],
            'role': result[3],
            'is_active': bool(result[4]),
            'is_verified': bool(result[5]),
            'created_at': result[6],
            'last_login': result[7]
        }
    
    def get_all_users(self) -> List[Dict]:
        """Get all users (admin only)"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, role, is_active, is_verified, created_at, last_login
            FROM users ORDER BY created_at DESC
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3],
                'is_active': bool(row[4]),
                'is_verified': bool(row[5]),
                'created_at': row[6],
                'last_login': row[7]
            })
        
        conn.close()
        return users
    
    def update_user_role(self, user_id: int, new_role: str) -> bool:
        """Update user role (admin only)"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET role = ? WHERE id = ?
        ''', (new_role, user_id))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            self._log_user_activity(user_id, 'role_updated', {'new_role': new_role})
        
        return affected > 0
    
    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate user account"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 0 WHERE id = ?
        ''', (user_id,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            self._log_user_activity(user_id, 'account_deactivated', {})
        
        return affected > 0
    
    def _log_user_activity(self, user_id: int, action: str, details: Dict, ip_address: str = None, user_agent: str = None):
        """Log user activity"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_activity (user_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, ip_address, user_agent, json.dumps(details)))
        
        conn.commit()
        conn.close()
    
    def get_user_activity(self, user_id: int = None, limit: int = 100) -> List[Dict]:
        """Get user activity log"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT ua.*, u.username
                FROM user_activity ua
                JOIN users u ON ua.user_id = u.id
                WHERE ua.user_id = ?
                ORDER BY ua.timestamp DESC
                LIMIT ?
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT ua.*, u.username
                FROM user_activity ua
                JOIN users u ON ua.user_id = u.id
                ORDER BY ua.timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        activities = []
        for row in cursor.fetchall():
            activities.append({
                'id': row[0],
                'user_id': row[1],
                'username': row[7],
                'action': row[2],
                'ip_address': row[3],
                'user_agent': row[4],
                'details': json.loads(row[5]) if row[5] else {},
                'timestamp': row[6]
            })
        
        conn.close()
        return activities
