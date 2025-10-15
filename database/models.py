import sqlite3
from datetime import datetime, timezone, timedelta
import json

# Kenya timezone (EAT - East Africa Time: UTC+3)
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
        Creates and returns a thread-safe SQLite connection.
        This allows the Flask app and background scanner to share the same database.
        """
        conn = sqlite3.connect(
            self.db_path,
            timeout=30,               # waits up to 30s if database is busy
            check_same_thread=False   # allow access from background threads
        )
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT UNIQUE NOT NULL,
                hostname TEXT,
                vendor TEXT,
                device_name TEXT,
                is_trusted INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'offline',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reconnect_count INTEGER DEFAULT 0,
                metadata TEXT,
                marked_safe INTEGER DEFAULT 0
            )
        ''')
        
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
        
        # Add new columns if they don't exist
        try:
            cursor.execute('ALTER TABLE alerts ADD COLUMN marked_safe INTEGER DEFAULT 0')
        except:
            pass
        
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN marked_safe INTEGER DEFAULT 0')
        except:
            pass
        
        conn.commit()
        conn.close()
        
        self._create_default_rules()
    
    def _create_default_rules(self):
        default_rules = [
            ('new_device_detected', 'device_event', 'device_first_seen', 1, 'high'),
            ('frequent_reconnect', 'device_event', 'reconnect_count', 10, 'medium'),
            ('device_inactive', 'device_event', 'inactive_duration', 7200, 'low'),
            ('suspicious_mac', 'device_event', 'mac_pattern', 1, 'high'),
            ('ip_change', 'device_event', 'ip_changed', 1, 'medium'),
            ('unknown_vendor', 'device_event', 'vendor_unknown', 1, 'low')
        ]
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        for rule in default_rules:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO rules (name, rule_type, condition, threshold, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', rule)
            except sqlite3.IntegrityError:
                pass
        
        conn.commit()
        conn.close()
    
    def add_device(self, ip, mac, hostname=None, vendor=None):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO devices (ip_address, mac_address, hostname, vendor, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'online', ?, ?)
            ''', (ip, mac, hostname, vendor, kenya_time, kenya_time))
            device_id = cursor.lastrowid
            conn.commit()
            return device_id
        except sqlite3.IntegrityError:
            # Device exists - update it
            cursor.execute('''
                UPDATE devices 
                SET ip_address = ?, last_seen = ?, status = 'online',
                    reconnect_count = reconnect_count + 1,
                    hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor)
                WHERE mac_address = ?
            ''', (ip, kenya_time, hostname, vendor, mac))
            conn.commit()
            cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (mac,))
            return cursor.fetchone()[0]
        finally:
            conn.close()
    
    def update_device_status(self, device_id, status):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE devices 
            SET status = ?, last_seen = ?
            WHERE id = ?
        ''', (status, kenya_time, device_id))
        conn.commit()
        conn.close()
    
    def delete_devices(self, device_ids):
        """Delete multiple devices by ID list"""
        conn = self.get_connection()
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(device_ids))
        
        # Delete related alerts first
        cursor.execute(f'DELETE FROM alerts WHERE device_id IN ({placeholders})', device_ids)
        
        # Delete related events
        cursor.execute(f'DELETE FROM events WHERE device_id IN ({placeholders})', device_ids)
        
        # Delete devices
        cursor.execute(f'DELETE FROM devices WHERE id IN ({placeholders})', device_ids)
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    
    def add_event(self, event_type, severity, description, device_id=None, metadata=None):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (timestamp, event_type, severity, description, device_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (kenya_time, event_type, severity, description, device_id, json.dumps(metadata) if metadata else None))
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return event_id
    
    def delete_events(self, event_ids=None):
        """Delete events - if no IDs provided, delete all"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if event_ids:
            placeholders = ','.join('?' * len(event_ids))
            cursor.execute(f'DELETE FROM events WHERE id IN ({placeholders})', event_ids)
        else:
            cursor.execute('DELETE FROM events')
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    
    def add_alert(self, alert_type, severity, title, description, device_id=None, metadata=None):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, title, description, device_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (kenya_time, alert_type, severity, title, description, device_id, json.dumps(metadata) if metadata else None))
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id
    
    def mark_alert_safe(self, alert_id):
        """Mark an alert as safe/false positive"""
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE alerts 
            SET marked_safe = 1, status = 'resolved', resolved_at = ?
            WHERE id = ?
        ''', (kenya_time, alert_id))
        conn.commit()
        conn.close()
    
    def delete_alerts(self, alert_ids=None):
        """Delete alerts - if no IDs provided, delete all resolved ones"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if alert_ids:
            placeholders = ','.join('?' * len(alert_ids))
            cursor.execute(f'DELETE FROM alerts WHERE id IN ({placeholders})', alert_ids)
        else:
            cursor.execute("DELETE FROM alerts WHERE status = 'resolved'")
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    
    def get_all_devices(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return devices
    
    def get_active_devices(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE status = 'online' ORDER BY last_seen DESC")
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return devices
    
    def get_recent_alerts(self, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.*, d.ip_address, d.mac_address, d.device_name 
            FROM alerts a
            LEFT JOIN devices d ON a.device_id = d.id
            WHERE a.status = 'active'
            ORDER BY a.timestamp DESC
            LIMIT ?
        ''', (limit,))
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts
    
    def get_recent_events(self, limit=100):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT e.*, d.ip_address, d.device_name 
            FROM events e
            LEFT JOIN devices d ON e.device_id = d.id
            ORDER BY e.timestamp DESC
            LIMIT ?
        ''', (limit,))
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return events
    
    def resolve_alert(self, alert_id):
        kenya_time = get_kenya_time()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE alerts 
            SET status = 'resolved', resolved_at = ?
            WHERE id = ?
        ''', (kenya_time, alert_id))
        conn.commit()
        conn.close()
    
    def get_dashboard_stats(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
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
        
        conn.close()
        
        return {
            'total_devices': total_devices,
            'active_devices': active_devices,
            'active_alerts': active_alerts,
            'critical_alerts': critical_alerts,
            'trusted_devices': trusted_devices,
            'new_today': new_today
        }