import sqlite3
from datetime import datetime, timezone, timedelta
import json
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Kenya timezone 
KENYA_TZ = timezone(timedelta(hours=3))

def get_kenya_time():
    """Get current time in Kenya timezone"""
    return datetime.now(KENYA_TZ).strftime('%Y-%m-%d %H:%M:%S')

class Database:
    def __init__(self, db_path='netwatch.db'):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """
        Creates and returns a thread-safe SQLite connection - FAST and SIMPLE
        WAL mode enabled for concurrency without retries (faster)
        """
        conn = sqlite3.connect(
            self.db_path,
            timeout=5,                # Short timeout - fail fast
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        
        # Enable WAL mode - fast concurrent access
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=5000')   # 5 seconds max wait
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA temp_store=MEMORY')   # Faster temp operations
        
        return conn
    
    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    vendor TEXT,
                    device_name TEXT,
                    is_trusted INTEGER DEFAULT 1,
                    risk_score INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'offline',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reconnect_count INTEGER DEFAULT 0,
                    metadata TEXT,
                    marked_safe INTEGER DEFAULT 0
                )
            ''')
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    description TEXT,
                    device_id INTEGER,
                    metadata TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    device_id INTEGER,
                    status TEXT DEFAULT 'active',
                    resolved_at TIMESTAMP,
                    metadata TEXT,
                    marked_safe INTEGER DEFAULT 0,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')
            
            # Rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    rule_type TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    threshold INTEGER,
                    severity TEXT DEFAULT 'medium',
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            ''')
            
            # Licenses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT UNIQUE,
                    license_type TEXT DEFAULT 'LITE',
                    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # System logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action TEXT NOT NULL,
                    user TEXT DEFAULT 'system',
                    details TEXT,
                    metadata TEXT
                )
            ''')
            
            # System config table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key TEXT UNIQUE NOT NULL,
                    config_value TEXT NOT NULL,
                    data_type TEXT DEFAULT 'string',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Users table (NEW)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'viewer',
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')
            
            # User sessions table (NEW)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # User activity table (NEW)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Adding new columns if they don't exist
            try:
                cursor.execute('ALTER TABLE alerts ADD COLUMN marked_safe INTEGER DEFAULT 0')
            except sqlite3.OperationalError:
                pass
            
            try:
                cursor.execute('ALTER TABLE devices ADD COLUMN marked_safe INTEGER DEFAULT 0')
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            print(f"Database initialization error: {e}")
            raise
        finally:
            conn.close()
        
        # Create default configuration and admin user
        self._create_default_config()
        self._create_default_admin()
    
    def _create_default_config(self):
        """Initialize default configuration settings"""
        default_config = [
            ('scan_interval', '60', 'integer'),
            ('scan_timeout', '5', 'integer'),
            ('alert_retention_days', '90', 'integer'),
            ('log_retention_days', '365', 'integer'),
            ('traffic_monitoring', 'true', 'boolean'),
            ('extended_logs', 'true', 'boolean'),
            ('email_alerts', 'true', 'boolean'),
            ('scanning_active', 'true', 'boolean')
        ]
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            for key, value, data_type in default_config:
                cursor.execute('''
                    INSERT OR IGNORE INTO system_config (config_key, config_value, data_type)
                    VALUES (?, ?, ?)
                ''', (key, value, data_type))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error creating default config: {e}")
        finally:
            conn.close()
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        import os
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            
            if user_count == 0:
                admin_username = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
                admin_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
                admin_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@netwatch.local')
                
                password_hash = generate_password_hash(admin_password)
                kenya_time = get_kenya_time()
                
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (admin_username, admin_email, password_hash, 'admin', 1, kenya_time))
                
                conn.commit()
                print(f"\n✓ Default admin user created: {admin_username} / {admin_password}")
                print("  Please change the password after first login!\n")
        except Exception as e:
            conn.rollback()
            print(f"Error creating default admin: {e}")
        finally:
            conn.close()
    
    def get_config(self, key=None):
        """Get configuration value(s) from database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if key:
                cursor.execute('SELECT config_value, data_type FROM system_config WHERE config_key = ?', (key,))
                result = cursor.fetchone()
                
                if result:
                    value, data_type = result
                    if data_type == 'integer':
                        return int(value)
                    elif data_type == 'boolean':
                        return value.lower() == 'true'
                    return value
                return None
            else:
                cursor.execute('SELECT config_key, config_value, data_type FROM system_config')
                results = cursor.fetchall()
                
                config = {}
                for row in results:
                    key, value, data_type = row
                    if data_type == 'integer':
                        config[key] = int(value)
                    elif data_type == 'boolean':
                        config[key] = value.lower() == 'true'
                    else:
                        config[key] = value
                return config
        finally:
            conn.close()
    
    def set_config(self, key, value):
        """Set configuration value in database"""
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Determine data type
            data_type = 'string'
            if isinstance(value, bool):
                data_type = 'boolean'
                value = 'true' if value else 'false'
            elif isinstance(value, int):
                data_type = 'integer'
                value = str(value)
            
            cursor.execute('''
                INSERT OR REPLACE INTO system_config (config_key, config_value, data_type, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (key, value, data_type, kenya_time))
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error setting config: {e}")
        finally:
            conn.close()
    
    def add_device(self, ip, mac, hostname=None, vendor=None):
        """
        Add or update device silently. Returns device_id.
        Handles UNIQUE constraint gracefully with proper transaction management.
        """
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Check if device exists by MAC address
            cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (mac,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing device
                device_id = existing[0]
                cursor.execute('''
                    UPDATE devices 
                    SET ip_address = ?, 
                        last_seen = ?, 
                        status = 'online',
                        reconnect_count = reconnect_count + 1,
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor)
                    WHERE id = ?
                ''', (ip, kenya_time, hostname, vendor, device_id))
                conn.commit()
                return device_id
            
            # Check by IP (for devices with generated MACs)
            cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip,))
            existing_by_ip = cursor.fetchone()
            
            if existing_by_ip:
                # Update existing device found by IP
                device_id = existing_by_ip[0]
                cursor.execute('''
                    UPDATE devices 
                    SET mac_address = ?, 
                        last_seen = ?, 
                        status = 'online',
                        reconnect_count = reconnect_count + 1,
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor)
                    WHERE id = ?
                ''', (mac, kenya_time, hostname, vendor, device_id))
                conn.commit()
                return device_id
            
            # Insert new device - default to trusted
            cursor.execute('''
                INSERT INTO devices (ip_address, mac_address, hostname, vendor, status, first_seen, last_seen, is_trusted)
                VALUES (?, ?, ?, ?, 'online', ?, ?, 1)
            ''', (ip, mac, hostname, vendor, kenya_time, kenya_time))
            device_id = cursor.lastrowid
            conn.commit()
            return device_id
                
        except sqlite3.IntegrityError:
            # UNIQUE constraint failed - try to get the device_id
            conn.rollback()
            try:
                cursor.execute('SELECT id FROM devices WHERE mac_address = ? OR ip_address = ?', (mac, ip))
                result = cursor.fetchone()
                if result:
                    return result[0]
            except:
                pass
            return None
            
        except Exception as e:
            conn.rollback()
            print(f"Error adding device: {e}")
            return None
        finally:
            conn.close()
    
    def update_device_status(self, device_id, status):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE devices 
                SET status = ?, last_seen = ?
                WHERE id = ?
            ''', (status, kenya_time, device_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error updating device status: {e}")
        finally:
            conn.close()
    
    def delete_devices(self, device_ids):
        """Delete multiple devices by ID list"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            placeholders = ','.join('?' * len(device_ids))
            
            # Delete related alerts first
            cursor.execute(f'DELETE FROM alerts WHERE device_id IN ({placeholders})', device_ids)
            
            # Delete related events
            cursor.execute(f'DELETE FROM events WHERE device_id IN ({placeholders})', device_ids)
            
            # Delete devices
            cursor.execute(f'DELETE FROM devices WHERE id IN ({placeholders})', device_ids)
            
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        except Exception as e:
            conn.rollback()
            print(f"Error deleting devices: {e}")
            return 0
        finally:
            conn.close()
    
    def add_event(self, event_type, severity, description, device_id=None, metadata=None):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO events (timestamp, event_type, severity, description, device_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (kenya_time, event_type, severity, description, device_id, json.dumps(metadata) if metadata else None))
            event_id = cursor.lastrowid
            conn.commit()
            return event_id
        except Exception as e:
            conn.rollback()
            print(f"Error adding event: {e}")
            return None
        finally:
            conn.close()
    
    def delete_events(self, event_ids=None):
        """Delete events... if no IDs provided, delete all"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if event_ids:
                placeholders = ','.join('?' * len(event_ids))
                cursor.execute(f'DELETE FROM events WHERE id IN ({placeholders})', event_ids)
            else:
                cursor.execute('DELETE FROM events')
            
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        except Exception as e:
            conn.rollback()
            print(f"Error deleting events: {e}")
            return 0
        finally:
            conn.close()
    
    def add_alert(self, alert_type, severity, title, description, device_id=None, metadata=None):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, severity, title, description, device_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (kenya_time, alert_type, severity, title, description, device_id, json.dumps(metadata) if metadata else None))
            alert_id = cursor.lastrowid
            conn.commit()
            return alert_id
        except Exception as e:
            conn.rollback()
            print(f"Error adding alert: {e}")
            return None
        finally:
            conn.close()
    
    def mark_alert_safe(self, alert_id):
        """Mark an alert as safe/false positive"""
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE alerts 
                SET marked_safe = 1, status = 'resolved', resolved_at = ?
                WHERE id = ?
            ''', (kenya_time, alert_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error marking alert safe: {e}")
        finally:
            conn.close()
    
    def delete_alerts(self, alert_ids=None):
        """Delete alerts... if no IDs provided, delete all resolved ones"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if alert_ids:
                placeholders = ','.join('?' * len(alert_ids))
                cursor.execute(f'DELETE FROM alerts WHERE id IN ({placeholders})', alert_ids)
            else:
                cursor.execute("DELETE FROM alerts WHERE status = 'resolved'")
            
            deleted_count = cursor.rowcount
            conn.commit()
            return deleted_count
        except Exception as e:
            conn.rollback()
            print(f"Error deleting alerts: {e}")
            return 0
        finally:
            conn.close()
    
    def get_all_devices(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
            devices = []
            for row in cursor.fetchall():
                device = dict(row)
                # Normalize device name for display - if no device_name or hostname, mark as None (will show as "Unknown" in frontend)
                if not device.get('device_name') and not device.get('hostname'):
                    device['display_name'] = None
                elif device.get('device_name'):
                    device['display_name'] = device['device_name']
                else:
                    device['display_name'] = device.get('hostname')
                devices.append(device)
            return devices
        finally:
            conn.close()

    def search_devices(self, query):
        """Search devices by IP, MAC, device name, hostname, or vendor"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            search_term = f"%{query}%"
            
            cursor.execute('''
                SELECT * FROM devices 
                WHERE ip_address LIKE ? 
                   OR mac_address LIKE ? 
                   OR device_name LIKE ? 
                   OR hostname LIKE ? 
                   OR vendor LIKE ?
                ORDER BY last_seen DESC
            ''', (search_term, search_term, search_term, search_term, search_term))
            
            devices = [dict(row) for row in cursor.fetchall()]
            return devices
        finally:
            conn.close()
    
    def get_active_devices(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices WHERE status = 'online' ORDER BY last_seen DESC")
            devices = [dict(row) for row in cursor.fetchall()]
            return devices
        finally:
            conn.close()
    
    def get_recent_alerts(self, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT a.*, d.ip_address, d.mac_address, d.device_name 
                FROM alerts a
                LEFT JOIN devices d ON a.device_id = d.id
                WHERE a.status = 'active'
                ORDER BY a.timestamp DESC
                LIMIT ?
            ''', (limit,))
            alerts = [dict(row) for row in cursor.fetchall()]
            return alerts
        finally:
            conn.close()
    
    def get_recent_events(self, limit=100):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT e.*, d.ip_address, d.device_name 
                FROM events e
                LEFT JOIN devices d ON e.device_id = d.id
                ORDER BY e.timestamp DESC
                LIMIT ?
            ''', (limit,))
            events = [dict(row) for row in cursor.fetchall()]
            return events
        finally:
            conn.close()
    
    def resolve_alert(self, alert_id):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE alerts 
                SET status = 'resolved', resolved_at = ?
                WHERE id = ?
            ''', (kenya_time, alert_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error resolving alert: {e}")
        finally:
            conn.close()
    
    def get_dashboard_stats(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT COUNT(*) as total FROM devices")
            total_devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as active FROM devices WHERE status = 'online'")
            active_devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as alerts FROM alerts WHERE status = 'active'")
            active_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as critical FROM alerts WHERE status = 'active' AND severity = 'high'")
            critical_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as trusted FROM devices WHERE is_trusted = 1")
            trusted_devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as new_today FROM devices WHERE DATE(first_seen) = DATE('now', '+3 hours')")
            new_today = cursor.fetchone()[0]
            
            return {
                'total_devices': total_devices,
                'active_devices': active_devices,
                'active_alerts': active_alerts,
                'critical_alerts': critical_alerts,
                'trusted_devices': trusted_devices,
                'new_today': new_today
            }
        finally:
            conn.close()


class UserManager:
    """Manages user authentication, sessions, and activity"""
    
    def __init__(self, db):
        self.db = db
    
    def register_user(self, username, email, password, role='viewer'):
        """Register a new user - FAST and SIMPLE with immediate commits"""
        conn = None
        try:
            # Get connection with immediate mode for faster writes
            conn = self.db.get_connection()
            conn.execute('BEGIN IMMEDIATE')  # Immediate mode - faster, less locking
            cursor = conn.cursor()
            
            # Quick check if username exists
            cursor.execute('SELECT id FROM users WHERE username = ? LIMIT 1', (username,))
            if cursor.fetchone():
                conn.rollback()
                conn.close()
                return {'success': False, 'error': 'Username already exists'}
            
            # Quick check if email exists
            cursor.execute('SELECT id FROM users WHERE email = ? LIMIT 1', (email,))
            if cursor.fetchone():
                conn.rollback()
                conn.close()
                return {'success': False, 'error': 'Email already exists'}
            
            # Hash password and insert
            password_hash = generate_password_hash(password)
            kenya_time = get_kenya_time()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
            ''', (username, email, password_hash, role, kenya_time))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            conn = None
            
            # Log activity in separate, fast transaction (don't wait for it)
            try:
                self._log_activity_async(user_id, username, 'user_registered', None, 'New user account created')
            except:
                pass
            
            return {'success': True, 'user_id': user_id}
            
        except sqlite3.IntegrityError:
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            return {'success': False, 'error': 'Username or email already exists'}
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            return {'success': False, 'error': f'Error: {str(e)}'}
    
    def authenticate_user(self, username, password, ip_address=None):
        """Authenticate user credentials"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, email, password_hash, role, is_active, failed_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                return {'success': False, 'error': 'Invalid username or password'}
            
            user_dict = dict(user)
            
            # Check if account is locked
            if user_dict['locked_until']:
                locked_until = datetime.fromisoformat(user_dict['locked_until'])
                if datetime.now(KENYA_TZ) < locked_until:
                    return {'success': False, 'error': 'Account is locked. Try again later.'}
            
            # Check if account is active
            if not user_dict['is_active']:
                return {'success': False, 'error': 'Account is disabled'}
            
            # Verify password
            if not check_password_hash(user_dict['password_hash'], password):
                # Increment failed attempts
                cursor.execute('''
                    UPDATE users SET failed_attempts = failed_attempts + 1
                    WHERE id = ?
                ''', (user_dict['id'],))
                
                # Lock account after 5 failed attempts
                if user_dict['failed_attempts'] >= 4:
                    locked_until = (datetime.now(KENYA_TZ) + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute('''
                        UPDATE users SET locked_until = ?
                        WHERE id = ?
                    ''', (locked_until, user_dict['id']))
                
                conn.commit()
                return {'success': False, 'error': 'Invalid username or password'}
            
            # Success - reset failed attempts and update last login
            kenya_time = get_kenya_time()
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = 0, locked_until = NULL, last_login = ?
                WHERE id = ?
            ''', (kenya_time, user_dict['id']))
            conn.commit()
            
            # Log activity
            self._log_activity(user_dict['id'], username, 'user_login', ip_address, 'User logged in')
            
            return {
                'success': True,
                'user': {
                    'id': user_dict['id'],
                    'username': user_dict['username'],
                    'email': user_dict['email'],
                    'role': user_dict['role']
                }
            }
            
        except Exception as e:
            conn.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            conn.close()
    
    def create_session(self, user_id, ip_address, user_agent):
        """Create a new session token for user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            session_token = secrets.token_urlsafe(32)
            kenya_time = get_kenya_time()
            expires_at = (datetime.now(KENYA_TZ) + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, session_token, ip_address, user_agent, kenya_time, expires_at))
            
            conn.commit()
            return session_token
            
        except Exception as e:
            conn.rollback()
            print(f"Error creating session: {e}")
            return None
        finally:
            conn.close()
    
    def get_all_users(self):
        """Get all users for admin panel"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users
                ORDER BY created_at DESC
            ''')
            
            users = [dict(row) for row in cursor.fetchall()]
            return users
        finally:
            conn.close()
    
    def deactivate_user(self, user_id):
        """Deactivate a user account"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            print(f"Error deactivating user: {e}")
            return False
        finally:
            conn.close()
    
    def get_user_activity(self, limit=100):
        """Get recent user activity"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT username, action, timestamp, ip_address, details
                FROM user_activity
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            activity = [dict(row) for row in cursor.fetchall()]
            return activity
        finally:
            conn.close()
    
    def _log_activity(self, user_id, username, action, ip_address, details):
        """Log user activity - synchronous"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            kenya_time = get_kenya_time()
            cursor.execute('''
                INSERT INTO user_activity (user_id, username, action, timestamp, ip_address, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, action, kenya_time, ip_address, details))
            conn.commit()
            conn.close()
        except:
            pass  # Silent fail - don't block on logging
    
    def _log_activity_async(self, user_id, username, action, ip_address, details):
        """Log user activity - async version (doesn't block)"""
        import threading
        def log():
            try:
                self._log_activity(user_id, username, action, ip_address, details)
            except:
                pass
        threading.Thread(target=log, daemon=True).start()