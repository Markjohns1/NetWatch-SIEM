import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'netwatch-siem-secret-key-2024')
    DATABASE_PATH = 'netwatch.db'
    
    SCAN_INTERVAL = 10
    SCAN_TIMEOUT = 5
    
    ALERT_RETENTION_DAYS = 90
    LOG_RETENTION_DAYS = 365
    
    LICENSE_TYPE = 'FULL'
    
    TRAFFIC_MONITORING = True
    EXTENDED_LOGS = True
    EMAIL_ALERTS = True
    ADVANCED_RULES = True
    
    RULES_CONFIG = {
        'new_device_alert': True,
        'reconnect_threshold': 5,
        'inactive_timeout': 3600,
        'suspicious_mac_prefixes': ['00:00:00', 'FF:FF:FF'],
        'traffic_spike_threshold': 1000000
    }
    
    ALERT_SETTINGS = {
        'enable_sound': True,
        'enable_popup': True,
        'enable_email': True
    }
