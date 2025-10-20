# COMPLETE FILE WITH 20+ CONDITIONS FOR FALSE POSITIVE REDUCTION

CONDITION_METADATA = {
    # DEVICE LIFECYCLE CONDITIONS
    'device_first_seen': {
        'label': 'New Device Detected',
        'description': 'Alert when a new device joins the network (first 1 hour window)',
        'threshold_type': 'number',
        'threshold_unit': 'hours',
        'threshold_min': 1,
        'threshold_max': 168,
        'threshold_default': 1,
        'threshold_help': 'Alert on devices detected within this many hours',
        'validation_text': 'Must be between 1 and 168 hours',
        'example': 'Alert on any device seen within the last 1 hour',
        'step': 1
    },
    
    'device_disappeared': {
        'label': 'Device Disappeared from Network',
        'description': 'Alert when a trusted device goes offline unexpectedly',
        'threshold_type': 'number',
        'threshold_unit': 'hours',
        'threshold_min': 1,
        'threshold_max': 168,
        'threshold_default': 4,
        'threshold_help': 'Alert if trusted device offline for X hours',
        'validation_text': 'Must be between 1 and 168 hours',
        'example': 'Alert if laptop offline for more than 4 hours',
        'step': 1
    },

    # RECONNECTION CONDITIONS
    'reconnect_count': {
        'label': 'Excessive Reconnections',
        'description': 'Alert when device reconnects too many times (possible spoofing or instability)',
        'threshold_type': 'number',
        'threshold_unit': 'reconnections',
        'threshold_min': 5,
        'threshold_max': 100,
        'threshold_default': 20,
        'threshold_help': 'Number of reconnections before alert (untrusted: 20+, trusted: 50+)',
        'validation_text': 'Must be between 5 and 100 reconnections',
        'example': 'Alert if device reconnects more than 20 times',
        'step': 1
    },
    
    'reconnect_frequency': {
        'label': 'Frequent Reconnections in Short Time',
        'description': 'Alert when device reconnects multiple times within a short period',
        'threshold_type': 'number',
        'threshold_unit': 'reconnections per 10 minutes',
        'threshold_min': 2,
        'threshold_max': 20,
        'threshold_default': 5,
        'threshold_help': 'How many reconnections in 10-minute window triggers alert',
        'validation_text': 'Must be between 2 and 20',
        'example': 'Alert if device reconnects 5+ times in 10 minutes',
        'step': 1
    },

    # MAC ADDRESS CONDITIONS
    'mac_pattern': {
        'label': 'Suspicious MAC Address Pattern',
        'description': 'Alert on known MAC spoofing and suspicious patterns',
        'threshold_type': 'select',
        'threshold_options': [
            {'value': 'common_spoof', 'label': 'Common spoofing (00:00:00, FF:FF:FF, etc.)'},
            {'value': 'vm_patterns', 'label': 'Virtual machine patterns (02:xx:xx, 52:54:xx)'},
            {'value': 'broadcast', 'label': 'Broadcast MAC (FF:FF:FF:FF:FF:FF)'},
            {'value': 'all_suspicious', 'label': 'All suspicious patterns'}
        ],
        'threshold_default': 'common_spoof',
        'threshold_help': 'Which MAC patterns should trigger alert',
        'validation_text': 'Select one pattern type',
        'example': 'Alert on MAC addresses like 00:00:00:00:00:00'
    },
    
    'mac_changed': {
        'label': 'MAC Address Changed',
        'description': 'Alert when device changes MAC address (spoofing indicator)',
        'threshold_type': 'boolean',
        'threshold_default': True,
        'threshold_help': 'Alert when same IP suddenly has different MAC',
        'validation_text': 'No threshold needed',
        'example': 'Alert if IP 192.168.1.100 switches MAC addresses'
    },

    # VENDOR CONDITIONS
    'vendor_unknown': {
        'label': 'Unknown Device Vendor',
        'description': 'Alert on devices with unidentifiable manufacturers (only for untrusted)',
        'threshold_type': 'boolean',
        'threshold_default': True,
        'threshold_help': 'Alert on devices with unknown vendors (skips trusted devices)',
        'validation_text': 'No threshold needed',
        'example': 'Alert on devices with unknown manufacturers'
    },
    
    'suspicious_vendor': {
        'label': 'Suspicious Device Manufacturer',
        'description': 'Alert on known malicious or risky device vendors',
        'threshold_type': 'select',
        'threshold_options': [
            {'value': 'generic', 'label': 'Generic/Unrecognized (high risk)'},
            {'value': 'china_origin', 'label': 'Devices from China origin vendors'},
            {'value': 'iot_generic', 'label': 'Generic IoT devices (esp. cameras)'},
            {'value': 'all', 'label': 'All suspicious manufacturers'}
        ],
        'threshold_default': 'generic',
        'threshold_help': 'Which vendor categories to alert on',
        'validation_text': 'Select vendor risk category',
        'example': 'Alert on generic unrecognized vendors'
    },

    # IP ADDRESS CONDITIONS
    'ip_changed': {
        'label': 'IP Address Changed',
        'description': 'Alert when trusted device gets new IP (possible compromised/spoofed)',
        'threshold_type': 'boolean',
        'threshold_default': True,
        'threshold_help': 'Alert when previously seen MAC gets different IP',
        'validation_text': 'No threshold needed',
        'example': 'Alert if trusted device switches to new IP address'
    },
    
    'rapid_ip_changes': {
        'label': 'Rapid IP Address Changes',
        'description': 'Alert when device cycles through IPs rapidly (DHCP exhaustion/spoofing)',
        'threshold_type': 'number',
        'threshold_unit': 'IP changes per hour',
        'threshold_min': 2,
        'threshold_max': 50,
        'threshold_default': 5,
        'threshold_help': 'How many different IPs for same MAC triggers alert',
        'validation_text': 'Must be between 2 and 50',
        'example': 'Alert if MAC has 5+ different IPs in an hour'
    },
    
    'private_ip_overlap': {
        'label': 'Private IP Range Anomaly',
        'description': 'Alert when device uses unusual private IP ranges',
        'threshold_type': 'select',
        'threshold_options': [
            {'value': 'unexpected_range', 'label': 'IPs outside normal subnet'},
            {'value': 'loopback', 'label': 'Loopback addresses (127.x.x.x)'},
            {'value': 'link_local', 'label': 'Link-local addresses (169.254.x.x)'},
            {'value': 'reserved', 'label': 'Reserved/invalid ranges'}
        ],
        'threshold_default': 'unexpected_range',
        'threshold_help': 'Which IP anomalies to alert on',
        'validation_text': 'Select IP range type',
        'example': 'Alert if device uses IP outside normal subnet'
    },

    # ACTIVITY CONDITIONS
    'inactive_duration': {
        'label': 'Device Offline Too Long',
        'description': 'Alert when device stays offline longer than expected',
        'threshold_type': 'number',
        'threshold_unit': 'hours',
        'threshold_min': 1,
        'threshold_max': 720,
        'threshold_default': 24,
        'threshold_help': 'Hours offline before alert (for tracking dormant devices)',
        'validation_text': 'Must be between 1 and 720 hours',
        'example': 'Alert if device offline for more than 24 hours'
    },
    
    'no_activity': {
        'label': 'No Network Activity',
        'description': 'Alert when online device sends no traffic (possible compromise)',
        'threshold_type': 'number',
        'threshold_unit': 'minutes',
        'threshold_min': 5,
        'threshold_max': 480,
        'threshold_default': 60,
        'threshold_help': 'Minutes without traffic before alert',
        'validation_text': 'Must be between 5 and 480 minutes',
        'example': 'Alert if device online but silent for 60+ minutes'
    },

    # NETWORK LOCATION CONDITIONS
    'location_change': {
        'label': 'Device Physical Location Changed',
        'description': 'Alert when device connects from different network segment (VLAN/subnet)',
        'threshold_type': 'boolean',
        'threshold_default': True,
        'threshold_help': 'Alert when MAC appears on different subnet/VLAN',
        'validation_text': 'No threshold needed',
        'example': 'Alert if laptop moves from office VLAN to guest VLAN'
    },
    
    'simultaneous_ips': {
        'label': 'Same MAC Multiple IPs Simultaneously',
        'description': 'Alert when single MAC has multiple IPs at same time (spoofing/DHCP issue)',
        'threshold_type': 'number',
        'threshold_unit': 'simultaneous IPs',
        'threshold_min': 2,
        'threshold_max': 10,
        'threshold_default': 2,
        'threshold_help': 'How many IPs from same MAC trigger alert',
        'validation_text': 'Must be between 2 and 10',
        'example': 'Alert if one MAC has 2+ active IPs at same time'
    },

    # BEHAVIOR CONDITIONS
    'abnormal_scan': {
        'label': 'Network Scanning Detected',
        'description': 'Alert when device performs port scanning or network reconnaissance',
        'threshold_type': 'number',
        'threshold_unit': 'ports scanned',
        'threshold_min': 10,
        'threshold_max': 1000,
        'threshold_default': 50,
        'threshold_help': 'How many unique ports accessed in 5 min window',
        'validation_text': 'Must be between 10 and 1000 ports',
        'example': 'Alert if device probes 50+ ports in 5 minutes'
    },
    
    'broadcast_storm': {
        'label': 'Broadcast Storm Detected',
        'description': 'Alert when device floods network with broadcast packets',
        'threshold_type': 'number',
        'threshold_unit': 'packets per second',
        'threshold_min': 100,
        'threshold_max': 10000,
        'threshold_default': 1000,
        'threshold_help': 'Broadcast packets per second threshold',
        'validation_text': 'Must be between 100 and 10000 pps',
        'example': 'Alert if device sends 1000+ broadcast packets/sec'
    },
    
    'arp_spoofing': {
        'label': 'ARP Spoofing Detected',
        'description': 'Alert on multiple devices claiming same IP or MAC-IP mismatches',
        'threshold_type': 'number',
        'threshold_unit': 'ARP conflicts',
        'threshold_min': 1,
        'threshold_max': 20,
        'threshold_default': 3,
        'threshold_help': 'How many ARP conflicts trigger alert',
        'validation_text': 'Must be between 1 and 20',
        'example': 'Alert after 3+ ARP conflicts for same IP'
    },

    # DEVICE TYPE CONDITIONS
    'unexpected_device_type': {
        'label': 'Unexpected Device Type',
        'description': 'Alert on devices of unexpected types in specific network areas',
        'threshold_type': 'select',
        'threshold_options': [
            {'value': 'phone_on_secure', 'label': 'Mobile device on secure network'},
            {'value': 'iot_on_corp', 'label': 'IoT device on corporate network'},
            {'value': 'camera_unusual', 'label': 'Cameras in unexpected locations'},
            {'value': 'iot_any', 'label': 'Any IoT device detected'}
        ],
        'threshold_default': 'iot_any',
        'threshold_help': 'Which unexpected device types to alert on',
        'validation_text': 'Select device type anomaly',
        'example': 'Alert when IoT camera detected on network'
    },

    # MULTI-CONDITION SCENARIOS
    'new_untrusted_behavior': {
        'label': 'New Device + Suspicious Behavior',
        'description': 'Alert when new device shows suspicious activity immediately',
        'threshold_type': 'select',
        'threshold_options': [
            {'value': 'immediate_scan', 'label': 'New device scans network immediately'},
            {'value': 'immediate_spoof', 'label': 'New device with spoofed MAC/IP'},
            {'value': 'immediate_high_traffic', 'label': 'New device with high traffic'},
            {'value': 'any_suspicious', 'label': 'Any suspicious activity'}
        ],
        'threshold_default': 'any_suspicious',
        'threshold_help': 'What suspicious behavior triggers alert',
        'validation_text': 'Select suspicious behavior type',
        'example': 'Alert if new device starts port scanning'
    },
    
    'repeated_failures': {
        'label': 'Repeated Connection Failures',
        'description': 'Alert when device repeatedly fails to authenticate or connect',
        'threshold_type': 'number',
        'threshold_unit': 'failures in 10 minutes',
        'threshold_min': 3,
        'threshold_max': 50,
        'threshold_default': 10,
        'threshold_help': 'How many auth failures trigger alert',
        'validation_text': 'Must be between 3 and 50',
        'example': 'Alert after 10 failed auth attempts in 10 min'
    }
}


def get_condition_label(condition_key):
    """Get user-friendly label for a condition"""
    return CONDITION_METADATA.get(condition_key, {}).get('label', condition_key)


def get_condition_metadata(condition_key):
    """Get full metadata for a condition"""
    return CONDITION_METADATA.get(condition_key, {})


def validate_threshold(condition_key, threshold_value):
    """Validate threshold value for a condition"""
    meta = CONDITION_METADATA.get(condition_key, {})
    threshold_type = meta.get('threshold_type')
    
    if threshold_type == 'boolean':
        return True, "Valid"
    
    elif threshold_type == 'select':
        options = meta.get('threshold_options', [])
        valid_values = [opt['value'] for opt in options]
        if threshold_value in valid_values:
            return True, "Valid"
        return False, f"Invalid selection. Must be one of: {', '.join(valid_values)}"
    
    elif threshold_type == 'number':
        try:
            if not threshold_value and threshold_value != 0:
                return False, "Threshold value is required"
                
            threshold_val = int(threshold_value)
            threshold_min = meta.get('threshold_min', 0)
            threshold_max = meta.get('threshold_max', 1000000)
            
            if threshold_val < threshold_min:
                return False, f"Threshold too low (minimum: {threshold_min})"
            if threshold_val > threshold_max:
                return False, f"Threshold too high (maximum: {threshold_max})"
            
            return True, "Valid"
        except (ValueError, TypeError):
            return False, "Threshold must be a number"
    
    return False, "Unknown threshold type"