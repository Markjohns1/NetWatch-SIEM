# Advanced Analytics and ML-powered Threat Detection for NetWatch SIEM
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json
import math

class ThreatAnalyzer:
    def __init__(self, db):
        self.db = db
        self.anomaly_threshold = 0.7
        self.behavioral_window = 24  # hours
        self.risk_weights = {
            'new_device': 0.8,
            'frequent_reconnect': 0.6,
            'suspicious_mac': 0.9,
            'unknown_vendor': 0.4,
            'offline_anomaly': 0.5,
            'traffic_spike': 0.7,
            'port_scan': 0.8,
            'dns_anomaly': 0.6
        }
    
    def calculate_network_health_score(self):
        """Calculate overall network health score (0-100)"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Get basic stats
            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
            online_devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active' AND severity = 'high'")
            critical_alerts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
            total_alerts = cursor.fetchone()[0]
            
            conn.close()
            
            # Calculate health score
            if total_devices == 0:
                return 100
            
            online_ratio = online_devices / total_devices
            alert_ratio = min(total_alerts / total_devices, 1.0) if total_devices > 0 else 0
            critical_ratio = min(critical_alerts / total_devices, 1.0) if total_devices > 0 else 0
            
            health_score = (
                online_ratio * 40 +  # 40% weight for online devices
                (1 - alert_ratio) * 30 +  # 30% weight for low alert ratio
                (1 - critical_ratio) * 30  # 30% weight for low critical alerts
            ) * 100
            
            return max(0, min(100, health_score))
            
        except Exception as e:
            print(f"Error calculating health score: {e}")
            return 50
    
    def detect_anomalies(self):
        """Detect network anomalies using statistical analysis"""
        anomalies = []
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Device activity anomalies
            cursor.execute('''
                SELECT ip_address, COUNT(*) as event_count, 
                       AVG(CASE WHEN event_type = 'device_scan' THEN 1 ELSE 0 END) as scan_ratio
                FROM events e
                JOIN devices d ON e.device_id = d.id
                WHERE e.timestamp >= datetime('now', '-24 hours')
                GROUP BY d.ip_address
                HAVING event_count > 50 OR scan_ratio > 0.8
            ''')
            
            for row in cursor.fetchall():
                anomalies.append({
                    'type': 'high_activity',
                    'device': row[0],
                    'severity': 'medium',
                    'description': f"Unusual high activity detected: {row[1]} events in 24h",
                    'confidence': min(row[1] / 100, 1.0)
                })
            
            # Time-based anomalies
            cursor.execute('''
                SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
                FROM events
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY hour
                ORDER BY count DESC
            ''')
            
            hourly_activity = cursor.fetchall()
            if hourly_activity:
                max_activity = hourly_activity[0][1]
                avg_activity = sum(row[1] for row in hourly_activity) / len(hourly_activity)
                
                if max_activity > avg_activity * 3:
                    anomalies.append({
                        'type': 'time_anomaly',
                        'severity': 'low',
                        'description': f"Unusual activity pattern detected at hour {hourly_activity[0][0]}",
                        'confidence': min((max_activity - avg_activity) / avg_activity, 1.0)
                    })
            
            conn.close()
            
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
        
        return anomalies
    
    def calculate_device_risk_scores(self):
        """Calculate risk scores for all devices"""
        risk_scores = {}
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT d.id, d.ip_address, d.mac_address, d.vendor, d.is_trusted,
                       COUNT(a.id) as alert_count,
                       COUNT(CASE WHEN a.severity = 'high' THEN 1 END) as high_alerts,
                       d.reconnect_count,
                       CASE WHEN d.vendor = 'Unknown' THEN 1 ELSE 0 END as unknown_vendor
                FROM devices d
                LEFT JOIN alerts a ON d.id = a.device_id AND a.status = 'active'
                GROUP BY d.id
            ''')
            
            for row in cursor.fetchall():
                device_id, ip, mac, vendor, is_trusted, alert_count, high_alerts, reconnect_count, unknown_vendor = row
                
                # Calculate risk score (0-100)
                risk_score = 0
                
                # Base risk factors
                if not is_trusted:
                    risk_score += 20
                
                if unknown_vendor:
                    risk_score += 15
                
                if alert_count > 0:
                    risk_score += min(alert_count * 10, 40)
                
                if high_alerts > 0:
                    risk_score += min(high_alerts * 15, 30)
                
                if reconnect_count > 10:
                    risk_score += min(reconnect_count * 2, 20)
                
                # MAC address risk
                if mac.startswith(('00:00:00', 'FF:FF:FF')):
                    risk_score += 25
                
                risk_scores[device_id] = {
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'risk_score': min(risk_score, 100),
                    'risk_level': self._get_risk_level(risk_score),
                    'factors': self._get_risk_factors(row)
                }
            
            conn.close()
            
        except Exception as e:
            print(f"Error calculating risk scores: {e}")
        
        return risk_scores
    
    def _get_risk_level(self, score):
        """Convert risk score to level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _get_risk_factors(self, device_data):
        """Get risk factors for a device"""
        factors = []
        device_id, ip, mac, vendor, is_trusted, alert_count, high_alerts, reconnect_count, unknown_vendor = device_data
        
        if not is_trusted:
            factors.append('Untrusted device')
        
        if unknown_vendor:
            factors.append('Unknown vendor')
        
        if alert_count > 0:
            factors.append(f'{alert_count} active alerts')
        
        if high_alerts > 0:
            factors.append(f'{high_alerts} high severity alerts')
        
        if reconnect_count > 10:
            factors.append(f'Frequent reconnections ({reconnect_count})')
        
        if mac.startswith(('00:00:00', 'FF:FF:FF')):
            factors.append('Suspicious MAC address')
        
        return factors
    
    def generate_threat_intelligence(self):
        """Generate threat intelligence report"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Get threat statistics
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT d.id) as total_devices,
                    COUNT(CASE WHEN d.status = 'online' THEN 1 END) as online_devices,
                    COUNT(CASE WHEN d.is_trusted = 1 THEN 1 END) as trusted_devices,
                    COUNT(CASE WHEN a.severity = 'high' THEN 1 END) as high_alerts,
                    COUNT(CASE WHEN a.severity = 'medium' THEN 1 END) as medium_alerts,
                    COUNT(CASE WHEN a.severity = 'low' THEN 1 END) as low_alerts
                FROM devices d
                LEFT JOIN alerts a ON d.id = a.device_id AND a.status = 'active'
            ''')
            
            stats = cursor.fetchone()
            
            # Get top vendors
            cursor.execute('''
                SELECT vendor, COUNT(*) as count
                FROM devices
                WHERE vendor != 'Unknown'
                GROUP BY vendor
                ORDER BY count DESC
                LIMIT 5
            ''')
            
            top_vendors = cursor.fetchall()
            
            # Get recent threat trends
            cursor.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as alert_count
                FROM alerts
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            ''')
            
            threat_trends = cursor.fetchall()
            
            conn.close()
            
            return {
                'network_stats': {
                    'total_devices': stats[0],
                    'online_devices': stats[1],
                    'trusted_devices': stats[2],
                    'high_alerts': stats[3],
                    'medium_alerts': stats[4],
                    'low_alerts': stats[5]
                },
                'top_vendors': [{'vendor': row[0], 'count': row[1]} for row in top_vendors],
                'threat_trends': [{'date': row[0], 'count': row[1]} for row in threat_trends],
                'health_score': self.calculate_network_health_score(),
                'anomalies': self.detect_anomalies(),
                'risk_scores': self.calculate_device_risk_scores()
            }
            
        except Exception as e:
            print(f"Error generating threat intelligence: {e}")
            return {}
    
    def predict_threats(self):
        """Predict potential threats using ML-like analysis"""
        predictions = []
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Predict devices likely to go offline
            cursor.execute('''
                SELECT d.ip_address, d.last_seen, d.reconnect_count
                FROM devices d
                WHERE d.status = 'online' 
                AND datetime(d.last_seen) < datetime('now', '-1 hour')
                AND d.reconnect_count > 5
            ''')
            
            for row in cursor.fetchall():
                predictions.append({
                    'type': 'device_offline_prediction',
                    'device': row[0],
                    'confidence': min(row[2] / 20, 1.0),
                    'description': f"Device {row[0]} may go offline soon (high reconnect count)"
                })
            
            # Predict potential security incidents
            cursor.execute('''
                SELECT d.ip_address, COUNT(a.id) as alert_count
                FROM devices d
                LEFT JOIN alerts a ON d.id = a.device_id AND a.status = 'active'
                WHERE d.is_trusted = 0
                GROUP BY d.id
                HAVING alert_count >= 3
            ''')
            
            for row in cursor.fetchall():
                predictions.append({
                    'type': 'security_incident_prediction',
                    'device': row[0],
                    'confidence': min(row[1] / 10, 1.0),
                    'description': f"Device {row[0]} shows signs of potential security incident"
                })
            
            conn.close()
            
        except Exception as e:
            print(f"Error predicting threats: {e}")
        
        return predictions

