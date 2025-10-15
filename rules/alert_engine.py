from datetime import datetime, timedelta
import json

class AlertEngine:
    def __init__(self, db):
        self.db = db
        self.rules = self._load_rules()
    
    def _load_rules(self):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules WHERE enabled = 1")
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rules
    
    def reload_rules(self):
        self.rules = self._load_rules()
    
    def check_new_device(self, device_id):
        """Check if device is new and hasn't been alerted before"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Check if device is actually new (first seen today)
        cursor.execute('''
            SELECT ip_address, mac_address, vendor, device_name, first_seen
            FROM devices 
            WHERE id = ? AND DATE(first_seen) = DATE('now')
        ''', (device_id,))
        device = cursor.fetchone()
        
        if not device:
            conn.close()
            return False
        
        # Check if we've already alerted about this device
        cursor.execute('''
            SELECT COUNT(*) as existing 
            FROM alerts 
            WHERE device_id = ? AND alert_type = 'new_device_detected'
        ''', (device_id,))
        existing = cursor.fetchone()[0]
        conn.close()
        
        # Only create alert if no previous alert exists
        if existing == 0:
            self.db.add_alert(
                alert_type='new_device_detected',
                severity='high',
                title='New Unknown Device Detected',
                description=f"New device joined the network: {device['ip_address']} ({device['mac_address']})",
                device_id=device_id,
                metadata={'ip': device['ip_address'], 'mac': device['mac_address'], 'vendor': device['vendor']}
            )
            return True
        return False
    
    def check_frequent_reconnect(self, device_id):
        """Check for frequent reconnections"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, mac_address, reconnect_count 
            FROM devices 
            WHERE id = ? AND reconnect_count >= 10
        ''', (device_id,))
        device = cursor.fetchone()
        
        if device:
            # Check if we already have an active alert
            cursor.execute('''
                SELECT COUNT(*) as existing 
                FROM alerts 
                WHERE device_id = ? 
                AND alert_type = 'frequent_reconnect' 
                AND status = 'active'
            ''', (device_id,))
            existing = cursor.fetchone()[0]
            conn.close()
            
            if existing == 0:
                self.db.add_alert(
                    alert_type='frequent_reconnect',
                    severity='medium',
                    title='Device Reconnected Multiple Times',
                    description=f"Device {device['ip_address']} has reconnected {device['reconnect_count']} times",
                    device_id=device_id,
                    metadata={'reconnect_count': device['reconnect_count']}
                )
                return True
        else:
            conn.close()
        return False
    
    def check_ip_change(self, device_id, old_ip, new_ip):
        """Check for IP address changes"""
        if old_ip != new_ip:
            self.db.add_alert(
                alert_type='ip_change',
                severity='medium',
                title='Trusted Device Changed IP Address',
                description=f"Device IP changed from {old_ip} to {new_ip}",
                device_id=device_id,
                metadata={'old_ip': old_ip, 'new_ip': new_ip}
            )
            return True
        return False
    
    def check_suspicious_mac(self, device_id, mac_address):
        """Check for suspicious MAC addresses"""
        suspicious_prefixes = ['00:00:00', 'FF:FF:FF']
        mac_prefix = mac_address[:8]
        
        if mac_prefix in suspicious_prefixes:
            # Check if we already alerted
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) 
                FROM alerts 
                WHERE device_id = ? AND alert_type = 'suspicious_mac'
            ''', (device_id,))
            existing = cursor.fetchone()[0]
            conn.close()
            
            if existing == 0:
                self.db.add_alert(
                    alert_type='suspicious_mac',
                    severity='high',
                    title='Suspicious MAC Address Detected',
                    description=f"Device has suspicious MAC address: {mac_address}",
                    device_id=device_id,
                    metadata={'mac': mac_address}
                )
                return True
        return False
    
    def check_unknown_vendor(self, device_id, vendor):
        """Check for unknown vendors - but don't spam alerts!"""
        # Skip if vendor is known
        if vendor != 'Unknown':
            return False
        
        # Check if we've already alerted about this device's unknown vendor
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) 
            FROM alerts 
            WHERE device_id = ? AND alert_type = 'unknown_vendor'
        ''', (device_id,))
        existing = cursor.fetchone()[0]
        conn.close()
        
        # Only alert once per device
        if existing == 0:
            self.db.add_alert(
                alert_type='unknown_vendor',
                severity='low',
                title='Device with Unknown Vendor',
                description=f"Device vendor could not be identified",
                device_id=device_id,
                metadata={'vendor': vendor}
            )
            return True
        return False
    
    def check_device_inactive(self):
        """Mark devices as offline if not seen in 2 hours (not 1 hour!)"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Use 2 hours instead of 1 hour to avoid false positives
        inactive_threshold = datetime.now() - timedelta(hours=2)
        cursor.execute('''
            SELECT id, ip_address, device_name, last_seen 
            FROM devices 
            WHERE datetime(last_seen) < ? AND status = 'online'
        ''', (inactive_threshold.strftime('%Y-%m-%d %H:%M:%S'),))
        
        devices = cursor.fetchall()
        conn.close()
        
        for device in devices:
            self.db.update_device_status(device['id'], 'offline')
            self.db.add_event(
                event_type='device_offline',
                severity='info',
                description=f"Device {device['ip_address']} went offline",
                device_id=device['id']
            )
    
    def process_device_alerts(self, device_id):
        """Process alerts for a device - prevents duplicates"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,) )
        device = cursor.fetchone()
        conn.close()
        
        if not device:
            return
        
        # Only check new device alert if device was just discovered
        # Calculate hours since first_seen
        try:
            first_seen = datetime.strptime(device['first_seen'], '%Y-%m-%d %H:%M:%S')
            hours_since_first = (datetime.now() - first_seen).total_seconds() / 3600
            
            # Only alert if device is less than 24 hours old
            if hours_since_first < 24:
                self.check_new_device(device_id)
        except:
            pass
        
        # Check reconnect count (only if excessive)
        if device['reconnect_count'] >= 10:
            self.check_frequent_reconnect(device_id)
        
        # Check suspicious MAC
        self.check_suspicious_mac(device_id, device['mac_address'])
        
        # Check unknown vendor (but only alert once per device)
        if device['vendor'] == 'Unknown' and device['is_trusted'] == 0:
            self.check_unknown_vendor(device_id, device['vendor'])
    
    def run_periodic_checks(self):
        """Run periodic maintenance checks"""
        self.check_device_inactive()