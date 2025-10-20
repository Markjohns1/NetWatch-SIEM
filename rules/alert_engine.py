
# Handles custom rules from database, not hardcoded checks

from datetime import datetime, timedelta
import json

class AlertEngine:
    """
    Alert Engine - Processes custom rules from database
    Works in conjunction with SmartAlertEngine for comprehensive threat detection
    """
    
    def __init__(self, db):
        self.db = db
        self.rules = self._load_rules()
        self.processed_alerts = {}  # Track processed alerts to avoid duplicates
    
    def _load_rules(self):
        """Load all enabled rules from database"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules WHERE enabled = 1 ORDER BY severity DESC, id ASC")
            rules = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rules
        except Exception as e:
            print(f"Error loading rules: {e}")
            return []
    
    def reload_rules(self):
        """Reload rules from database (called after rule changes)"""
        self.rules = self._load_rules()
    
    def _get_device_data(self, device_id):
        """Get current device data from database"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
            device = cursor.fetchone()
            conn.close()
            return dict(device) if device else None
        except Exception as e:
            print(f"Error getting device data: {e}")
            return None
    
    def _check_alert_exists(self, device_id, rule_name):
        """Check if alert already exists for this device/rule combination"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM alerts 
                WHERE device_id = ? AND alert_type = ? AND is_resolved = 0
            ''', (device_id, rule_name))
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception as e:
            print(f"Error checking alert exists: {e}")
            return False
    
    def evaluate_rule(self, rule, device):
        """
        Evaluate a single rule against a device
        Returns True if rule triggers, False otherwise
        """
        try:
            condition = rule['condition']
            threshold = rule['threshold']
            device_id = device['id']
            
            # Skip if alert already exists
            if self._check_alert_exists(device_id, rule['name']):
                return False
            
            triggered = False
            description = ""
            
            #device lifecycle
            if condition == 'device_first_seen':
                first_seen = datetime.strptime(device['first_seen'], '%Y-%m-%d %H:%M:%S')
                hours_old = (datetime.now() - first_seen).total_seconds() / 3600
                
                # Only alert on untrusted devices
                if hours_old <= threshold and device.get('is_trusted', 0) == 0:
                    triggered = True
                    description = f"New untrusted device detected: {device['ip_address']} ({device['mac_address']})"
            
            elif condition == 'device_disappeared':
                if device['status'] == 'offline' and device.get('is_trusted', 0) == 1:
                    last_seen = datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')
                    hours_offline = (datetime.now() - last_seen).total_seconds() / 3600
                    
                    if hours_offline >= threshold:
                        triggered = True
                        description = f"Trusted device offline for {int(hours_offline)} hours"
            
            #  RECONNECTIONS 
            elif condition == 'reconnect_count':
                if device.get('reconnect_count', 0) >= threshold:
                    triggered = True
                    description = f"Device reconnected {device['reconnect_count']} times (threshold: {threshold})"
            
            elif condition == 'reconnect_frequency':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM events
                    WHERE device_id = ? 
                    AND event_type = 'device_online'
                    AND datetime(timestamp) >= datetime('now', '-10 minutes')
                ''', (device_id,))
                recent_count = cursor.fetchone()[0]
                conn.close()
                
                if recent_count >= threshold:
                    triggered = True
                    description = f"Device reconnected {recent_count} times in 10 minutes"
            
            #  MAC ADDRESS 
            elif condition == 'mac_pattern':
                suspicious_patterns = {
                    'common_spoof': ['00:00:00', 'FF:FF:FF', '00:11:22', '33:33:33'],
                    'vm_patterns': ['02:00:00', '03:00:00', '52:54:00', '08:00:27'],
                    'broadcast': ['FF:FF:FF'],
                    'all_suspicious': ['00:00:00', 'FF:FF:FF', '00:11:22', '33:33:33', '02:00:00', '03:00:00', '52:54:00', '08:00:27']
                }
                
                patterns = suspicious_patterns.get(threshold, [])
                mac_prefix = device['mac_address'][:8]
                
                if any(mac_prefix.startswith(p[:8]) for p in patterns) and device.get('is_trusted', 0) == 0:
                    triggered = True
                    description = f"Suspicious MAC pattern detected: {device['mac_address']}"
            
            elif condition == 'mac_changed':
                # Check if this MAC has had multiple IPs
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) FROM events 
                    WHERE device_id = ? AND event_type IN ('device_online', 'ip_changed')
                ''', (device_id,))
                unique_ips = cursor.fetchone()[0]
                conn.close()
                
                if unique_ips > 1:
                    triggered = True
                    description = f"MAC address has associated with multiple IPs"
            
            #  VENDOR 
            elif condition == 'vendor_unknown':
                if device['vendor'] == 'Unknown' and device.get('is_trusted', 0) == 0:
                    triggered = True
                    description = f"Device with unknown vendor: {device['ip_address']}"
            
            elif condition == 'suspicious_vendor':
                # This is a placeholder - can be expanded with vendor lists
                triggered = False
            
            #  IP ADDRESS 
            elif condition == 'ip_changed':
                # Alert if trusted device's IP changed
                if device.get('is_trusted', 0) == 1:
                    conn = self.db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT COUNT(DISTINCT ip_address) FROM devices 
                        WHERE mac_address = ?
                    ''', (device['mac_address'],))
                    ip_count = cursor.fetchone()[0]
                    conn.close()
                    
                    if ip_count > 1:
                        triggered = True
                        description = f"Trusted device IP address changed"
            
            elif condition == 'rapid_ip_changes':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) FROM events
                    WHERE device_id = ? 
                    AND datetime(timestamp) >= datetime('now', '-1 hour')
                ''', (device_id,))
                ip_changes = cursor.fetchone()[0]
                conn.close()
                
                if ip_changes >= threshold:
                    triggered = True
                    description = f"Device cycled through {ip_changes} IPs in 1 hour"
            
            elif condition == 'private_ip_overlap':
                # Check for unusual IP ranges
                triggered = False  # Placeholder for future implementation
            
            #  ACTIVITY 
            elif condition == 'inactive_duration':
                if device['status'] == 'offline':
                    last_seen = datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')
                    hours_offline = (datetime.now() - last_seen).total_seconds() / 3600
                    
                    if hours_offline >= threshold:
                        triggered = True
                        description = f"Device offline for {int(hours_offline)} hours"
            
            elif condition == 'no_activity':
                # Placeholder - requires traffic monitoring
                triggered = False
            
            #  NETWORK LOCATION 
            elif condition == 'location_change':
                # Placeholder - requires VLAN/subnet tracking
                triggered = False
            
            elif condition == 'simultaneous_ips':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) FROM devices 
                    WHERE mac_address = ? AND status = 'online'
                ''', (device['mac_address'],))
                active_ips = cursor.fetchone()[0]
                conn.close()
                
                if active_ips >= threshold:
                    triggered = True
                    description = f"One MAC has {active_ips} simultaneous IPs"
            
            #  BEHAVIOR 
            elif condition == 'abnormal_scan':
                # Placeholder - requires port scanning detection
                triggered = False
            
            elif condition == 'broadcast_storm':
                # Placeholder - requires broadcast monitoring
                triggered = False
            
            elif condition == 'arp_spoofing':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM events
                    WHERE device_id = ? 
                    AND event_type = 'arp_conflict'
                    AND datetime(timestamp) >= datetime('now', '-1 hour')
                ''', (device_id,))
                conflicts = cursor.fetchone()[0]
                conn.close()
                
                if conflicts >= threshold:
                    triggered = True
                    description = f"Detected {conflicts} ARP conflicts"
            
            #  DEVICE TYPE 
            elif condition == 'unexpected_device_type':
                # Placeholder - requires device type classification
                triggered = False
            
            #  MULTI-CONDITION 
            elif condition == 'new_untrusted_behavior':
                # Placeholder - requires behavior analysis
                triggered = False
            
            elif condition == 'repeated_failures':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM events
                    WHERE device_id = ? 
                    AND event_type = 'auth_failure'
                    AND datetime(timestamp) >= datetime('now', '-10 minutes')
                ''', (device_id,))
                failures = cursor.fetchone()[0]
                conn.close()
                
                if failures >= threshold:
                    triggered = True
                    description = f"Device had {failures} auth failures"
            
            # Create alert if triggered
            if triggered:
                self.db.add_alert(
                    alert_type=rule['name'],
                    severity=rule.get('severity', 'medium'),
                    title=f"Alert: {rule['name']}",
                    description=description,
                    device_id=device_id,
                    metadata={
                        'rule_id': rule['id'],
                        'condition': condition,
                        'threshold': threshold
                    }
                )
                return True
            
            return False
            
        except Exception as e:
            print(f"Error evaluating rule {rule['name']}: {e}")
            return False
    
    def process_device_alerts(self, device_id):
        """Process all rules for a device"""
        device = self._get_device_data(device_id)
        
        if not device:
            return
        
        # Reload latest rules
        self.reload_rules()
        
        # Evaluate each rule
        for rule in self.rules:
            try:
                self.evaluate_rule(rule, device)
            except Exception as e:
                print(f"Error processing rule {rule.get('name', 'unknown')}: {e}")
    
    def run_periodic_checks(self):
        """Run periodic maintenance tasks"""
        try:
            # Check for devices that should be marked offline
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Mark devices offline if not seen in 5 seconds
            inactive_threshold = datetime.now() - timedelta(seconds=5)
            cursor.execute('''
                SELECT id, ip_address 
                FROM devices 
                WHERE datetime(last_seen) < ? AND status = 'online'
            ''', (inactive_threshold.strftime('%Y-%m-%d %H:%M:%S'),))
            
            offline_devices = cursor.fetchall()
            conn.close()
            
            for device in offline_devices:
                self.db.update_device_status(device['id'], 'offline')
                self.db.add_event(
                    event_type='device_offline',
                    severity='info',
                    description=f"Device {device['ip_address']} went offline",
                    device_id=device['id']
                )
        
        except Exception as e:
            print(f"Error in periodic checks: {e}")