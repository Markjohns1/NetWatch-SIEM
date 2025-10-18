from datetime import datetime, timedelta
import json
import hashlib

class SmartAlertEngine:
    def __init__(self, db):
        self.db = db
        self.rules = self._load_rules()
        self.alert_cache = {}  # Prevent duplicate alerts
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
            SELECT device_id, COUNT(*) as alert_count, 
                   MAX(timestamp) as last_alert
            FROM alerts 
            WHERE timestamp > datetime('now', '-30 days')
            GROUP BY device_id
        """)
        learning = cursor.fetchall()
        conn.close()
        return {device['device_id']: device for device in learning}
    
    def _generate_alert_hash(self, device_id, rule_name, condition_data):
        """Generate unique hash to prevent duplicate alerts"""
        hash_string = f"{device_id}_{rule_name}_{json.dumps(condition_data, sort_keys=True)}"
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def _is_whitelisted(self, device):
        """Check if device is whitelisted or trusted"""
        # Check MAC whitelist
        for trusted in self.device_whitelist:
            if device['mac_address'] == trusted['mac_address']:
                return True
        
        # Check if device is marked as trusted
        if device.get('is_trusted', 0) == 1:
            return True
            
        return False
    
    def _calculate_risk_score(self, device, rule):
        """Calculate dynamic risk score based on context"""
        base_score = {'low': 1, 'medium': 3, 'high': 5}[rule['severity']]
        
        # Reduce score for trusted devices
        if self._is_whitelisted(device):
            base_score *= 0.3
        
        # Increase score for devices with history of alerts
        device_id = device['id']
        if device_id in self.learning_data:
            alert_history = self.learning_data[device_id]['alert_count']
            if alert_history > 5:  # Frequent offender
                base_score *= 1.5
        
        # Reduce score for known vendors
        if device.get('vendor') and device['vendor'] != 'Unknown':
            base_score *= 0.8
        
        return min(base_score, 10)  # Cap at 10
    
    def _should_alert(self, device, rule, condition_met):
        """Smart decision on whether to create alert"""
        if not condition_met:
            return False
        
        # Skip if device is whitelisted and rule allows it
        if self._is_whitelisted(device) and rule.get('skip_trusted', True):
            return False
        
        # Check for recent similar alerts (prevent spam)
        alert_hash = self._generate_alert_hash(
            device['id'], 
            rule['name'], 
            {'condition': rule['condition'], 'threshold': rule['threshold']}
        )
        
        if alert_hash in self.alert_cache:
            last_alert = self.alert_cache[alert_hash]
            # Don't alert again within cooldown period
            if (datetime.now() - last_alert).total_seconds() < rule.get('cooldown', 3600):
                return False
        
        return True
    
    def evaluate_smart_rule(self, rule, device):
        """Enhanced rule evaluation with context awareness"""
        try:
            condition = rule['condition']
            threshold = rule['threshold']
            device_id = device['id']
            
            # Check if we should skip this rule for this device
            if not self._should_alert(device, rule, True):
                return False
            
            triggered = False
            description = ""
            risk_score = self._calculate_risk_score(device, rule)
            
            # Enhanced condition evaluation
            if condition == 'device_first_seen':
                # Only alert if device is truly new (within 1 hour) AND not trusted
                first_seen = datetime.strptime(device['first_seen'], '%Y-%m-%d %H:%M:%S')
                hours_old = (datetime.now() - first_seen).total_seconds() / 3600
                
                if hours_old <= 1 and not self._is_whitelisted(device):
                    triggered = True
                    description = f"New untrusted device: {device['ip_address']} ({device['mac_address']})"
            
            elif condition == 'reconnect_count':
                # Only alert for excessive reconnects (20+) and not trusted devices
                if device['reconnect_count'] >= threshold and not self._is_whitelisted(device):
                    triggered = True
                    description = f"Device reconnected {device['reconnect_count']} times (threshold: {threshold})"
            
            elif condition == 'inactive_duration':
                # Only alert for long-term inactive devices (24+ hours)
                last_seen = datetime.strptime(device['last_seen'], '%Y-%m-%d %H:%M:%S')
                inactive_hours = (datetime.now() - last_seen).total_seconds() / 3600
                
                if inactive_hours >= threshold and device['status'] == 'offline':
                    triggered = True
                    description = f"Device inactive for {int(inactive_hours)} hours"
            
            elif condition == 'mac_pattern':
                # Enhanced MAC pattern detection
                suspicious_patterns = [
                    '00:00:00', 'FF:FF:FF', '00:11:22',  # Common spoofing patterns
                    '02:00:00', '03:00:00'  # Virtual machine patterns
                ]
                mac_prefix = device['mac_address'][:8]
                
                if mac_prefix in suspicious_patterns and not self._is_whitelisted(device):
                    triggered = True
                    description = f"Suspicious MAC pattern: {device['mac_address']}"
            
            elif condition == 'vendor_unknown':
                # Only alert for unknown vendors on untrusted devices
                if (device['vendor'] == 'Unknown' and 
                    not self._is_whitelisted(device) and 
                    device.get('is_trusted', 0) == 0):
                    triggered = True
                    description = f"Unknown vendor device: {device['ip_address']}"
            
            elif condition == 'ip_changed':
                # This would need IP change tracking - implement if needed
                pass
            
            # Create alert if rule was triggered
            if triggered:
                # Update alert cache
                alert_hash = self._generate_alert_hash(device_id, rule['name'], {
                    'condition': condition, 'threshold': threshold
                })
                self.alert_cache[alert_hash] = datetime.now()
                
                # Adjust severity based on risk score
                if risk_score >= 7:
                    severity = 'high'
                elif risk_score >= 4:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                self.db.add_alert(
                    alert_type=rule['name'],
                    severity=severity,
                    title=f"Smart Alert: {rule['name']}",
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
            return False
    
    def process_smart_alerts(self, device_id):
        """Process alerts with smart logic - NO DUPLICATES"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        device_row = cursor.fetchone()
        conn.close()
        
        if not device_row:
            return
        
        # Convert SQLite Row to dictionary
        device = dict(device_row)
        
        # Reload rules and learning data
        self.rules = self._load_rules()
        self.learning_data = self._load_learning_data()
        
        # Process ONLY custom rules (no hardcoded duplicates)
        for rule in self.rules:
            try:
                self.evaluate_smart_rule(rule, device)
            except Exception as e:
                print(f"Error processing rule {rule['name']}: {e}")
    
    def run_smart_periodic_checks(self):
        """Run periodic checks with smart logic"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Check for devices that have been offline for 24+ hours
        inactive_threshold = datetime.now() - timedelta(hours=24)
        cursor.execute('''
            SELECT id, ip_address, device_name, last_seen 
            FROM devices 
            WHERE datetime(last_seen) < ? AND status = 'online'
        ''', (inactive_threshold.strftime('%Y-%m-%d %H:%M:%S'),))
        
        devices = cursor.fetchall()
        conn.close()
        
        for device in devices:
            self.db.update_device_status(device['id'], 'offline')
            # Only create event, not alert (too noisy)
            self.db.add_event(
                event_type='device_offline',
                severity='info',
                description=f"Device {device['ip_address']} went offline",
                device_id=device['id']
            )
    
    def add_rule_validation(self, rule_data):
        """Validate new rule before adding"""
        errors = []
        
        # Check for duplicate rule names
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM rules WHERE name = ?', (rule_data['name'],))
        if cursor.fetchone()[0] > 0:
            errors.append("Rule name already exists")
        
        # Validate threshold values
        if rule_data['condition'] == 'reconnect_count' and rule_data['threshold'] < 5:
            errors.append("Reconnect threshold too low (minimum 5)")
        
        if rule_data['condition'] == 'inactive_duration' and rule_data['threshold'] < 3600:
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
        
        # Convert SQLite Row to dictionary
        device = dict(device_row)
        
        # Create temporary rule for testing
        temp_rule = {
            'id': 'test',
            'name': rule_data['name'],
            'condition': rule_data['condition'],
            'threshold': rule_data['threshold'],
            'severity': rule_data['severity'],
            'enabled': 1
        }
        
        # Test the rule
        result = self.evaluate_smart_rule(temp_rule, device)
        
        return {
            "would_trigger": result,
            "device_info": {
                "ip": device['ip_address'],
                "mac": device['mac_address'],
                "vendor": device['vendor'],
                "trusted": device.get('is_trusted', 0)
            }
        }
