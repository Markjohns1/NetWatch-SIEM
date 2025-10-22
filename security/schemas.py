"""
Input validation schemas for NetWatch SIEM
Defines validation rules for all API endpoints
"""

# Device management schemas
DEVICE_TRUST_SCHEMA = {
    'is_trusted': {'type': 'bool', 'required': True}
}

DEVICE_NAME_SCHEMA = {
    'name': {'type': 'str', 'required': True, 'max_length': 100}
}

DEVICE_DELETE_SCHEMA = {
    'device_ids': {'type': 'list', 'required': True}
}

# Alert management schemas
ALERT_DELETE_SCHEMA = {
    'alert_ids': {'type': 'list', 'required': False},
    'delete_resolved': {'type': 'bool', 'required': False}
}

# Configuration schemas
CONFIG_SAVE_SCHEMA = {
    'scan_interval': {'type': 'int', 'required': False, 'min': 30, 'max': 600},
    'scanning_active': {'type': 'bool', 'required': False},
    'traffic_monitoring': {'type': 'bool', 'required': False},
    'extended_logs': {'type': 'bool', 'required': False},
    'email_alerts': {'type': 'bool', 'required': False},
    'rules': {'type': 'dict', 'required': False}
}

# Rule management schemas
RULE_ADD_SCHEMA = {
    'name': {'type': 'str', 'required': True, 'min_length': 3, 'max_length': 50},
    'rule_type': {'type': 'str', 'required': True},
    'condition': {'type': 'str', 'required': True},
    'threshold': {'type': 'int', 'required': True, 'min': 1},
    'severity': {'type': 'str', 'required': True}
}

RULE_UPDATE_SCHEMA = {
    'name': {'type': 'str', 'required': True, 'min_length': 3, 'max_length': 50},
    'condition': {'type': 'str', 'required': True},
    'threshold': {'type': 'int', 'required': True, 'min': 1},
    'severity': {'type': 'str', 'required': True}
}

RULE_TOGGLE_SCHEMA = {
    'enabled': {'type': 'bool', 'required': True}
}

RULE_TEST_SCHEMA = {
    'name': {'type': 'str', 'required': True, 'min_length': 3, 'max_length': 50},
    'condition': {'type': 'str', 'required': True},
    'threshold': {'type': 'int', 'required': True, 'min': 1},
    'severity': {'type': 'str', 'required': True},
    'device_id': {'type': 'int', 'required': True}
}

# Language management schemas
LANGUAGE_SET_SCHEMA = {
    'language': {'type': 'str', 'required': True, 'max_length': 5}
}

# Event management schemas
EVENT_DELETE_SCHEMA = {
    'event_ids': {'type': 'list', 'required': False},
    'delete_all': {'type': 'bool', 'required': False}
}

# Search schemas
DEVICE_SEARCH_SCHEMA = {
    'q': {'type': 'str', 'required': False, 'max_length': 100}
}

# Valid values for enum fields
VALID_SEVERITIES = ['low', 'medium', 'high']
VALID_RULE_TYPES = ['device_event', 'network_event', 'security_event']
VALID_CONDITIONS = [
    'device_first_seen', 'reconnect_count', 'inactive_duration',
    'mac_pattern', 'vendor_unknown', 'ip_changed'
]
VALID_LANGUAGES = ['en', 'es', 'fr', 'de', 'zh']

def validate_enum_field(value, valid_values, field_name):
    """Validate enum field values"""
    if value not in valid_values:
        return f"{field_name} must be one of: {', '.join(valid_values)}"
    return None

def validate_rule_data(data):
    """Comprehensive rule validation"""
    errors = []
    
    # Validate severity
    if 'severity' in data:
        error = validate_enum_field(data['severity'], VALID_SEVERITIES, 'severity')
        if error:
            errors.append(error)
    
    # Validate rule_type
    if 'rule_type' in data:
        error = validate_enum_field(data['rule_type'], VALID_RULE_TYPES, 'rule_type')
        if error:
            errors.append(error)
    
    # Validate condition
    if 'condition' in data:
        error = validate_enum_field(data['condition'], VALID_CONDITIONS, 'condition')
        if error:
            errors.append(error)
    
    # Validate language
    if 'language' in data:
        error = validate_enum_field(data['language'], VALID_LANGUAGES, 'language')
        if error:
            errors.append(error)
    
    return errors
