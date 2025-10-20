# File: rules/smart_alert_engine.py
# COMPLETE AND CORRECTED VERSION - FIXES "no such column: ip_address" ERROR

from datetime import datetime, timedelta
import json
import hashlib

class SmartAlertEngine:
    def __init__(self, db):
        self.db = db
        self.rules = self._load_rules()
        self.alert_cache = {}
        self.device_whitelist = self._load_whitelist()
        self.learning_data = self._load_learning_data()
    
    def _load_rules(self):
        """Load enabled rules with proper ordering"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM rules 
            WHERE enabled = 1 
            ORDER BY severity DESC, id ASC
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rules
    
    def _load_whitelist(self):
        """Load trusted devices and patterns"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT mac_address, ip_address FROM devices WHERE is_trusted = 1")
        whitelist = cursor.fetchall()
        conn.close()
        return [dict(device) for device in whitelist]
    
    def _load_learning_data(self):
        """Load historical patterns for smart detection"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT device_id, COUNT(*) as alert_count, MAX(timestamp) as last_alert
            FROM alerts 
            WHERE timestamp > datetime('now', '-30 days')
            GROUP BY device_id
        """)
        learning = cursor.fetchall()
        conn.close()
        return {dict(device)['device_id']: dict(device) for device in learning}
    
    def _generate_alert_hash(self, device_id, rule_name, condition_data):
        """Generate unique hash to prevent duplicate alerts"""
        hash_string = f"{device_id}_{rule_name}_{json.dumps(condition_data, sort_keys=True)}"
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def _is_whitelisted(self, device):
        """Check if device is whitelisted or trusted"""
        for trusted in self.device_whitelist:
            if device['mac_address'] == trusted['mac_address']:
                return True
        if device.get('is_trusted', 0) == 1:
            return True
        return False
    
    def _calculate_risk_score(self, device, rule):
        """Calculate dynamic risk score based on context"""
        base_score = {'low': 1, 'medium': 3, 'high': 5}[rule['severity']]
        
        if self._is_whitelisted(device):
            base_score *= 0.3
        
        device_id = device['id']
        if device_id in self.learning_data:
            alert_history = self.learning_data[device_id]['alert_count']
            if alert_history > 5:
                base_score *= 1.5
        
        if device.get('vendor') and device['vendor'] != 'Unknown':
            base_score *= 0.8
        
        return min(base_score, 10)
    
    def _should_alert(self, device, rule, condition_met):
        """Smart decision on whether to create alert"""
        if not condition_met:
            return False
        
        if self._is_whitelisted(device) and rule.get('skip_trusted', True):
            return False
        
        alert_hash = self._generate_alert_hash(
            device['id'], rule['name'], 
            {'condition': rule['condition'], 'threshold': rule.get('threshold')}
        )
        
        if alert_hash in self.alert_cache:
            last_alert = self.alert_cache[alert_hash]
            if (datetime.now() - last_alert).total_seconds() < rule.get('cooldown', 3600):
                return False
        
        return True
    
    def _get_ip_history(self, device_id):
        """Get device reconnection history - FIXED: removed ip_address from SELECT"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, metadata
            FROM events 
            WHERE device_id = ? AND event_type IN ('device_online', 'ip_changed')
            ORDER BY timestamp DESC LIMIT 20
        ''', (device_id,))
        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return history
    
    def _count_recent_arp_conflicts(self, device_id):
        """Count ARP conflicts for a device - FIXED: removed unused device_ip parameter"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM events
            WHERE device_id = ? 
            AND event_type = 'arp_conflict'
            AND datetime(timestamp) >= datetime('now', '-1 hour')
        ''', (device_id,))
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def evaluate_smart_rule(self, rule, device):
        """Enhanced rule evaluation with comprehensive condition logic"""
        try:
            condition = rule['condition']
            threshold = rule.get('threshold', 0)
            device_id = device['id']
            
            # Ensure device has required fields
            if not device.get('ip_address') or not device.get('mac_address'):
                return False
            
            if not self._should_alert(device, rule, True):
                return False
            
            triggered = False
            description = ""
            risk_score = self._calculate_risk_score(device, rule)
            
            # Device Lifecycle Conditions
            if condition == 'device_first_seen':
                first_seen = datetime.strptime(device['first_seen'], '%Y-%m-%d %H:%M:%S')
                hours_old = (datetime.now() - first_seen).total_seconds() / 3600
                
                if hours_old <= threshold and not self._is_whitelisted(device):
                    triggered = True
                    description = f"New untrusted device: {device['ip_address']} ({device['mac_address']})"
            
            elif condition == 'device_disappeared':
                if device['status'] == 'offline' and self._is_whitelisted(device):
                    last_seen = datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')
                    hours_offline = (datetime.now() - last_seen).total_seconds() / 3600
                    
                    if hours_offline >= threshold:
                        triggered = True
                        description = f"Trusted device offline for {int(hours_offline)} hours: {device['device_name'] or device['ip_address']}"
            
            # Reconnection Conditions
            elif condition == 'reconnect_count':
                min_threshold = 50 if self._is_whitelisted(device) else 20
                if device.get('reconnect_count', 0) >= max(threshold, min_threshold):
                    triggered = True
                    description = f"Device {device['ip_address']} reconnected {device['reconnect_count']} times (threshold: {threshold})"
            
            elif condition == 'reconnect_frequency':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM events
                    WHERE device_id = ? 
                    AND event_type = 'device_online'
                    AND datetime(timestamp) >= datetime('now', '-10 minutes')
                ''', (device_id,))
                recent_reconnects = cursor.fetchone()[0]
                conn.close()
                
                if recent_reconnects >= threshold:
                    triggered = True
                    description = f"Device {device['ip_address']} reconnected {recent_reconnects} times in 10 minutes (threshold: {threshold})"
            
            # MAC Address Conditions
            elif condition == 'mac_pattern':
                suspicious_patterns = {
                    'common_spoof': ['00:00:00', 'FF:FF:FF', '00:11:22', '33:33:33'],
                    'vm_patterns': ['02:00:00', '03:00:00', '52:54:00', '08:00:27'],
                    'broadcast': ['FF:FF:FF'],
                }
                
                mac_prefix = device['mac_address'][:8]
                patterns = suspicious_patterns.get(str(threshold), [])
                
                if any(mac_prefix.startswith(p[:8]) for p in patterns) and not self._is_whitelisted(device):
                    triggered = True
                    description = f"Suspicious MAC pattern: {device['mac_address']} on {device['ip_address']}"
            
            elif condition == 'mac_changed':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                # Check if this IP has been associated with different MACs
                cursor.execute('''
                    SELECT COUNT(DISTINCT mac_address) 
                    FROM devices 
                    WHERE ip_address = ?
                ''', (device['ip_address'],))
                
                unique_macs = cursor.fetchone()[0]
                conn.close()
                
                if unique_macs > 1:
                    triggered = True
                    description = f"MAC address changed for IP {device['ip_address']}"
            
            # Vendor Conditions
            elif condition == 'vendor_unknown':
                if device.get('vendor') == 'Unknown' and not self._is_whitelisted(device):
                    triggered = True
                    description = f"Device with unknown vendor: {device['ip_address']} ({device['mac_address']})"
            
            elif condition == 'suspicious_vendor':
                # Placeholder for suspicious vendor detection
                triggered = False
            
            # IP Address Conditions
            elif condition == 'ip_changed':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                
                # Check if this MAC had different IPs
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) 
                    FROM devices 
                    WHERE mac_address = ?
                ''', (device['mac_address'],))
                
                ip_count = cursor.fetchone()[0]
                conn.close()
                
                if ip_count > 1 and self._is_whitelisted(device):
                    triggered = True
                    description = f"Trusted device changed IP address: MAC {device['mac_address']} now at {device['ip_address']}"
            
            elif condition == 'rapid_ip_changes':
                ip_history = self._get_ip_history(device_id)
                last_hour_ips = [ip for ip in ip_history 
                                if datetime.strptime(ip['timestamp'], '%Y-%m-%d %H:%M:%S') 
                                > datetime.now() - timedelta(hours=1)]
                
                if len(last_hour_ips) >= threshold:
                    triggered = True
                    description = f"Device {device['ip_address']} had {len(last_hour_ips)} reconnections in 1 hour (threshold: {threshold})"
            
            elif condition == 'private_ip_overlap':
                # Placeholder for IP range anomaly detection
                triggered = False
            
            # Activity Conditions
            elif condition == 'inactive_duration':
                if device['status'] == 'offline':
                    last_seen = datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')
                    inactive_hours = (datetime.now() - last_seen).total_seconds() / 3600
                    
                    if inactive_hours >= threshold:
                        triggered = True
                        description = f"Device {device['ip_address']} inactive for {int(inactive_hours)} hours"
            
            elif condition == 'no_activity':
                # Placeholder for no network activity detection
                triggered = False
            
            # Network Location Conditions
            elif condition == 'location_change':
                # Placeholder for location change detection
                triggered = False
            
            elif condition == 'simultaneous_ips':
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip_address) 
                    FROM devices 
                    WHERE mac_address = ? AND status = 'online'
                ''', (device['mac_address'],))
                active_ips = cursor.fetchone()[0]
                conn.close()
                
                if active_ips >= threshold:
                    triggered = True
                    description = f"MAC {device['mac_address']} has {active_ips} simultaneous IPs (threshold: {threshold})"
            
            # Behavior Conditions
            elif condition == 'abnormal_scan':
                # Placeholder for network scanning detection
                triggered = False
            
            elif condition == 'broadcast_storm':
                # Placeholder for broadcast storm detection
                triggered = False
            
            elif condition == 'arp_spoofing':
                arp_conflicts = self._count_recent_arp_conflicts(device_id)
                
                if arp_conflicts >= threshold:
                    triggered = True
                    description = f"Detected {arp_conflicts} ARP conflicts for {device['ip_address']} (threshold: {threshold})"
            
            # Device Type Conditions
            elif condition == 'unexpected_device_type':
                # Placeholder for unexpected device type detection
                triggered = False
            
            # Multi-Condition Scenarios
            elif condition == 'new_untrusted_behavior':
                # Placeholder for new device suspicious behavior
                triggered = False
            
            elif condition == 'repeated_failures':
                # Placeholder for repeated failures detection
                triggered = False
            
            # Create alert if rule was triggered
            if triggered:
                alert_hash = self._generate_alert_hash(device_id, rule['name'], {
                    'condition': condition, 'threshold': threshold
                })
                self.alert_cache[alert_hash] = datetime.now()
                
                if risk_score >= 7:
                    severity = 'high'
                elif risk_score >= 4:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                self.db.add_alert(
                    alert_type=rule['name'],
                    severity=severity,
                    title=f"Alert: {rule['name']}",
                    description=description,
                    device_id=device_id,
                    metadata={
                        'rule_id': rule['id'],
                        'threshold': threshold,
                        'risk_score': risk_score,
                        'condition': condition,
                        'device_trusted': self._is_whitelisted(device)
                    }
                )
                return True
            
            return False
            
        except Exception as e:
            print(f"Error evaluating smart rule {rule['name']}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def process_smart_alerts(self, device_id):
        """Process alerts with smart logic - NO DUPLICATES"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Explicitly select all columns to ensure proper dict conversion
        cursor.execute('''
            SELECT id, ip_address, mac_address, hostname, vendor, 
                   device_name, is_trusted, risk_score, status, 
                   first_seen, last_seen, reconnect_count, metadata, marked_safe
            FROM devices WHERE id = ?
        ''', (device_id,))
        
        device_row = cursor.fetchone()
        conn.close()
        
        if not device_row:
            return
        
        device = dict(device_row)
        
        # Reload rules and learning data
        self.rules = self._load_rules()
        self.learning_data = self._load_learning_data()
        
        for rule in self.rules:
            try:
                self.evaluate_smart_rule(rule, device)
            except Exception as e:
                print(f"Error processing rule {rule['name']}: {e}")
    
    def run_smart_periodic_checks(self):
        """Run periodic checks with smart logic"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        inactive_threshold = datetime.now() - timedelta(hours=24)
        cursor.execute('''
            SELECT id, ip_address, device_name, last_seen 
            FROM devices 
            WHERE datetime(last_seen) < ? AND status = 'online'
        ''', (inactive_threshold.strftime('%Y-%m-%d %H:%M:%S'),))
        
        devices = cursor.fetchall()
        conn.close()
        
        for device in devices:
            device_dict = dict(device)
            self.db.update_device_status(device_dict['id'], 'offline')
            self.db.add_event(
                event_type='device_offline',
                severity='info',
                description=f"Device {device_dict['ip_address']} went offline",
                device_id=device_dict['id']
            )
    
    def add_rule_validation(self, rule_data):
        """Validate new rule before adding"""
        errors = []
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM rules WHERE name = ?', (rule_data['name'],))
        if cursor.fetchone()[0] > 0:
            errors.append("Rule name already exists")
        
        condition = rule_data.get('condition')
        threshold = rule_data.get('threshold')
        
        if condition == 'reconnect_count' and threshold < 5:
            errors.append("Reconnect threshold too low (minimum 5)")
        
        if condition == 'inactive_duration' and threshold < 1:
            errors.append("Inactive duration too short (minimum 1 hour)")
        
        conn.close()
        return errors
    
    def test_rule(self, rule_data, test_device_id):
        """Test rule against specific device"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (test_device_id,))
        device_row = cursor.fetchone()
        conn.close()
        
        if not device_row:
            return {"error": "Device not found"}
        
        device = dict(device_row)
        
        temp_rule = {
            'id': 'test',
            'name': rule_data['name'],
            'condition': rule_data['condition'],
            'threshold': rule_data.get('threshold', 0),
            'severity': rule_data['severity'],
            'enabled': 1
        }
        
        result = self.evaluate_smart_rule(temp_rule, device)
        
        return {
            "would_trigger": result,
            "device_info": {
                "ip": device['ip_address'],
                "mac": device['mac_address'],
                "vendor": device.get('vendor', 'Unknown'),
                "trusted": device.get('is_trusted', 0)
            }
        }