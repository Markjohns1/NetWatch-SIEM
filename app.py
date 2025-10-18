from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from functools import wraps
from database.models import Database
from scanner.device_scanner import DeviceScanner
from rules.alert_engine import AlertEngine
from rules.smart_alert_engine import SmartAlertEngine
from flask.signals import appcontext_pushed
from i18n import I18nManager
import threading
import time
from datetime import datetime
import os
from datetime import datetime, timedelta
from scanner.device_scanner import Colors
import logging

# Silence Flask and SocketIO logging completely
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

#app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'netwatch-siem-secret-key-2024')
app.logger.setLevel(logging.ERROR)  # Silence Flask app logger too

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", logger=False, engineio_logger=False)

# Initialize internationalization
i18n = I18nManager()
i18n.init_app(app)

# Use environment variables for credentials with fallback to defaults
VALID_USERNAME = os.environ.get('ADMIN_USERNAME', 'Mark')
VALID_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'lizzyjohn')


#login protection
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


db = Database()

# Force enable scanning on startup
db.set_config('scanning_active', True)
print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Auto-enabling network scanner...")

scanner = DeviceScanner(db, verbose=False, show_banner=True)
smart_alert_engine = SmartAlertEngine(db)
alert_engine = AlertEngine(db)

# Get initial config from database
scan_interval = db.get_config('scan_interval') or 60
scanning_active = db.get_config('scanning_active') or False
SCAN_INTERVAL = scan_interval

scanner_thread = None
_scanner_started = False  # Track if scanner started once


def _scanner_loop(app):
    """
    Runs the network scanner in a background thread.
    Must run inside app context so DB access works.
    Always checks DB for current scanning_active state.
    """
    with app.app_context():
        global SCAN_INTERVAL
        previous_devices = set()  # Track previous scan results
        
        # Loop while scanning is enabled in database
        while True:
            # Always check current scanning state from database
            current_scanning_active = db.get_config('scanning_active')
            if current_scanning_active is None:
                current_scanning_active = True  # Default if not set
                
            if not current_scanning_active:
                break  # Exit thread if scanning disabled
            
            try:
                # Reload scan interval from config before each scan
                current_interval = db.get_config('scan_interval') or 60
                SCAN_INTERVAL = current_interval
                
                # Scan network devices (silently)
                devices = scanner.scan_network()

                # Get current device statuses for comparison
                current_devices = set()
                device_status_changes = []
                
                # Process alerts for each detected device
                for device_dict in devices:
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('SELECT id, status FROM devices WHERE mac_address = ?', (device_dict['mac'],))
                    result = cursor.fetchone()

                    if result:
                        device_id, old_status = result
                        current_devices.add(device_id)
                        
                        # Check if device came online
                        if old_status == 'offline':
                            device_status_changes.append({
                                'device_id': device_id,
                                'ip': device_dict['ip'],
                                'mac': device_dict['mac'],
                                'status': 'online',
                                'change': 'came_online'
                            })
                            print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}[ONLINE]{Colors.RESET} {device_dict['ip']} ({device_dict['mac']})")
                        
                        smart_alert_engine.process_smart_alerts(device_id)
                    else:
                        # New device detected
                        current_devices.add(device_dict.get('id', 0))
                        device_status_changes.append({
                            'device_id': device_dict.get('id', 0),
                            'ip': device_dict['ip'],
                            'mac': device_dict['mac'],
                            'status': 'online',
                            'change': 'new_device'
                        })
                        print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_CYAN}[NEW]{Colors.RESET} {device_dict['ip']} ({device_dict['mac']}) - {device_dict.get('vendor', 'Unknown')}")

                    conn.close()

                # Check for devices that went offline
                offline_devices = previous_devices - current_devices
                for device_id in offline_devices:
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('SELECT ip_address, mac_address FROM devices WHERE id = ?', (device_id,))
                    result = cursor.fetchone()
                    if result:
                        ip, mac = result
                        device_status_changes.append({
                            'device_id': device_id,
                            'ip': ip,
                            'mac': mac,
                            'status': 'offline',
                            'change': 'went_offline'
                        })
                        print(f"{Colors.RED}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.RED}[OFFLINE]{Colors.RESET} {ip} ({mac})")
                    conn.close()

                # Emit real-time updates via WebSocket
                if device_status_changes:
                    socketio.emit('device_status_update', {
                        'changes': device_status_changes,
                        'timestamp': datetime.now().isoformat(),
                        'total_devices': len(current_devices)
                    })
                
                # Emit dashboard stats update
                stats = db.get_dashboard_stats()
                socketio.emit('dashboard_stats_update', {
                    'stats': stats,
                    'timestamp': datetime.now().isoformat()
                })

                # Update previous devices set
                previous_devices = current_devices

                # Run periodic rule checks with smart engine
                smart_alert_engine.run_smart_periodic_checks()

            except Exception as e:
                print(f"{Colors.RED}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.RED}[ERROR]{Colors.RESET} Scanner error: {e}")

            time.sleep(SCAN_INTERVAL)

def start_background_scanner():
    """
    Starts the background scanner thread safely once.
    Only starts if scanning_active is enabled in config.
    """
    global scanner_thread, _scanner_started
    
    # Only prevent restart if thread is already running
    if _scanner_started and scanner_thread and scanner_thread.is_alive():
        return  # Already running - don't print anything
    
    # If already tried to start, don't spam messages
    if _scanner_started:
        return
    
    # Check if scanning is enabled in config before starting
    scanning_enabled = db.get_config('scanning_active')
    if scanning_enabled is None:
        scanning_enabled = True  # Default to enabled if not set
        db.set_config('scanning_active', True)  # Save default
    
    if scanning_enabled:
        scanner_thread = threading.Thread(target=_scanner_loop, args=(app,), daemon=True)
        scanner_thread.start()
        _scanner_started = True
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}✓ Background scanning: ACTIVE{Colors.RESET}\n")
    else:
        _scanner_started = True  # Mark as attempted to prevent spam
        print(f"{Colors.YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.YELLOW}⚠ Background scanning: DISABLED{Colors.RESET}\n")


def _on_appcontext_pushed(sender, **extra):
    start_background_scanner()

# Connect the signal to start scanner when app context is pushed
appcontext_pushed.connect(_on_appcontext_pushed, app)



# ROUTES


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    if 'logged_in' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


@app.route('/devices')
@login_required
def devices_page():
    return render_template('devices.html')


@app.route('/alerts')
@login_required
def alerts_page():
    return render_template('alerts.html')


@app.route('/logs')
@login_required
def logs_page():
    return render_template('logs.html')


@app.route('/config')
@login_required
def config_page():
    return render_template('config.html')


@app.route('/api/dashboard/stats')
@login_required
def get_dashboard_stats():
    try:
        stats = db.get_dashboard_stats()
        return jsonify({'success': True, 'data': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices')
@login_required
def get_devices():
    try:
        devices = db.get_all_devices()
        return jsonify({'success': True, 'data': devices})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/search')
@login_required
def search_devices():
    try:
        query = request.args.get('q', '').strip()
        
        if not query:
            # Return all devices if no search query
            devices = db.get_all_devices()
        else:
            # Search devices
            devices = db.search_devices(query)
        
        return jsonify({'success': True, 'data': devices})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/active')
@login_required
def get_active_devices():
    try:
        devices = db.get_active_devices()
        return jsonify({'success': True, 'data': devices})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<int:device_id>/trust', methods=['POST'])
@login_required
def toggle_device_trust(device_id):
    try:
        data = request.json
        is_trusted = data.get('is_trusted', 0)
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE devices SET is_trusted = ? WHERE id = ?', (is_trusted, device_id))
        conn.commit()
        conn.close()
        
        db.add_event(
            event_type='device_trust_changed',
            severity='info',
            description=f"Device trust status changed to {'trusted' if is_trusted else 'untrusted'}",
            device_id=device_id
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<int:device_id>/name', methods=['POST'])
@login_required
def update_device_name(device_id):
    try:
        data = request.json
        device_name = data.get('name', '')
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE devices SET device_name = ? WHERE id = ?', (device_name, device_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts')
@login_required
def get_alerts():
    try:
        limit = request.args.get('limit', 50, type=int)
        alerts = db.get_recent_alerts(limit)
        return jsonify({'success': True, 'data': alerts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    try:
        db.resolve_alert(alert_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/events')
@login_required
def get_events():
    try:
        limit = request.args.get('limit', 100, type=int)
        events = db.get_recent_events(limit)
        return jsonify({'success': True, 'data': events})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/status')
@login_required
def scan_status():
    # Always read from database to get current values
    current_interval = db.get_config('scan_interval') or 60
    current_scanning = db.get_config('scanning_active')
    if current_scanning is None:
        current_scanning = True
    return jsonify({'success': True, 'scanning': current_scanning, 'interval': current_interval})


@app.route('/api/scan/now', methods=['POST'])
@login_required
def scan_now():
    try:
        devices = scanner.scan_network()
        
        for device_dict in devices:
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (device_dict['mac'],))
            result = cursor.fetchone()
            
            if result:
                device_id = result[0]
                smart_alert_engine.process_smart_alerts(device_id)
            
            conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Scan complete. Found {len(devices)} devices.',
            'devices_count': len(devices)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/activity/timeline')
@login_required
def get_activity_timeline():
    """
    Returns real-time activity data grouped by minute (last 2 hours)
    Updates continuously as events are created
    """
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get events from last 2 hours, grouped by minute
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:%M:00', timestamp) as minute,
                COUNT(*) as count
            FROM events
            WHERE datetime(timestamp) >= datetime('now', '-120 minutes')
            GROUP BY minute
            ORDER BY minute ASC
        ''')
        
        timeline_data = [{'time': row[0], 'count': row[1]} for row in cursor.fetchall()]
        conn.close()
        
        # If no data, return empty array (chart will show empty but won't error)
        return jsonify({'success': True, 'data': timeline_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analytics/device-trends')
@login_required
def get_device_trends():
    """Get device trends over time"""
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Device count over last 7 days
        cursor.execute('''
            SELECT 
                DATE(first_seen) as date,
                COUNT(*) as new_devices
            FROM devices
            WHERE datetime(first_seen) >= datetime('now', '-7 days')
            GROUP BY DATE(first_seen)
            ORDER BY date ASC
        ''')
        
        device_trends = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Device status distribution
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM devices
            GROUP BY status
        ''')
        
        status_distribution = [{'status': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Vendor distribution
        cursor.execute('''
            SELECT vendor, COUNT(*) as count
            FROM devices
            WHERE vendor != 'Unknown'
            GROUP BY vendor
            ORDER BY count DESC
            LIMIT 10
        ''')
        
        vendor_distribution = [{'vendor': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': {
                'device_trends': device_trends,
                'status_distribution': status_distribution,
                'vendor_distribution': vendor_distribution
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analytics/alert-trends')
@login_required
def get_alert_trends():
    """Get alert trends and patterns"""
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Alert count over last 7 days
        cursor.execute('''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_alerts,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_alerts,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_alerts,
                COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_alerts
            FROM alerts
            WHERE datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        ''')
        
        alert_trends = []
        for row in cursor.fetchall():
            alert_trends.append({
                'date': row[0],
                'total': row[1],
                'high': row[2],
                'medium': row[3],
                'low': row[4]
            })
        
        # Alert types distribution
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            WHERE datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY alert_type
            ORDER BY count DESC
        ''')
        
        alert_types = [{'type': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Hourly alert distribution
        cursor.execute('''
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM alerts
            WHERE datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour ASC
        ''')
        
        hourly_alerts = [{'hour': int(row[0]), 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': {
                'alert_trends': alert_trends,
                'alert_types': alert_types,
                'hourly_alerts': hourly_alerts
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analytics/network-health')
@login_required
def get_network_health():
    """Get network health metrics"""
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Basic network stats
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
        online_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM devices WHERE is_trusted = 1")
        trusted_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
        active_alerts = cursor.fetchone()[0]
        
        # Calculate health score
        if total_devices > 0:
            online_ratio = online_devices / total_devices
            trusted_ratio = trusted_devices / total_devices
            alert_ratio = min(active_alerts / total_devices, 1.0)
            
            health_score = (
                online_ratio * 40 +  # 40% weight for online devices
                trusted_ratio * 30 +  # 30% weight for trusted devices
                (1 - alert_ratio) * 30  # 30% weight for low alert ratio
            ) * 100
        else:
            health_score = 100
        
        # Device risk levels
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN reconnect_count > 20 THEN 'high'
                    WHEN reconnect_count > 10 THEN 'medium'
                    WHEN reconnect_count > 5 THEN 'low'
                    ELSE 'minimal'
                END as risk_level,
                COUNT(*) as count
            FROM devices
            GROUP BY risk_level
        ''')
        
        risk_levels = [{'level': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Recent activity (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*) FROM events
            WHERE datetime(timestamp) >= datetime('now', '-24 hours')
        ''')
        recent_activity = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': {
                'total_devices': total_devices,
                'online_devices': online_devices,
                'trusted_devices': trusted_devices,
                'active_alerts': active_alerts,
                'health_score': round(health_score, 1),
                'risk_levels': risk_levels,
                'recent_activity': recent_activity
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config')
@login_required
def get_config():
    try:
        # Get all config from database - always fresh
        db_config = db.get_config() or {}
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT name, enabled FROM rules')
        rules_data = cursor.fetchall()
        rules_dict = {row['name']: bool(row['enabled']) for row in rules_data}
        conn.close()
        
        config_data = {
            'scan_interval': db_config.get('scan_interval', 60),
            'scanning_active': db_config.get('scanning_active', True),
            'license_type': 'FULL',
            'traffic_monitoring': db_config.get('traffic_monitoring', True),
            'extended_logs': db_config.get('extended_logs', True),
            'email_alerts': db_config.get('email_alerts', True),
            'rules': {
                'new_device_alert': rules_dict.get('new_device_detected', True),
                'reconnect_alert': rules_dict.get('frequent_reconnect', True),
                'suspicious_mac_alert': rules_dict.get('suspicious_mac', True),
                'traffic_monitoring': db_config.get('traffic_monitoring', True),
                'advanced_logging': db_config.get('extended_logs', True)
            }
        }
        
        return jsonify({'success': True, 'data': config_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/delete', methods=['POST'])
@login_required
def delete_devices():
    try:
        data = request.json
        device_ids = data.get('device_ids', [])
        
        if not device_ids:
            return jsonify({'success': False, 'error': 'No devices specified'}), 400
        
        deleted_count = db.delete_devices(device_ids)
        
        db.add_event(
            event_type='devices_deleted',
            severity='info',
            description=f"Deleted {deleted_count} device(s) from system"
        )
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/mark-safe', methods=['POST'])
@login_required
def mark_alert_safe(alert_id):
    try:
        db.mark_alert_safe(alert_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/delete', methods=['POST'])
@login_required
def delete_alerts():
    try:
        data = request.json
        alert_ids = data.get('alert_ids', [])
        
        if alert_ids:
            deleted_count = db.delete_alerts(alert_ids)
        else:
            # Delete all resolved alerts
            deleted_count = db.delete_alerts()
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/events/delete', methods=['POST'])
@login_required
def delete_events():
    try:
        data = request.json
        event_ids = data.get('event_ids', [])
        
        if event_ids:
            deleted_count = db.delete_events(event_ids)
        else:
            # Delete all events
            deleted_count = db.delete_events()
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/timezone/info')
@login_required
def get_timezone_info():
    from datetime import datetime, timezone, timedelta
    kenya_tz = timezone(timedelta(hours=3))
    kenya_time = datetime.now(kenya_tz)
    
    return jsonify({
        'success': True,
        'timezone': 'Africa/Nairobi (EAT)',
        'offset': '+03:00',
        'current_time': kenya_time.strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/api/language/set', methods=['POST'])
@login_required
def set_language():
    try:
        data = request.json
        language = data.get('language', 'en')
        
        if i18n.set_language(language):
            return jsonify({
                'success': True,
                'message': 'Language updated successfully',
                'current_language': language
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid language code'
            }), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/language/current')
@login_required
def get_current_language():
    try:
        current_lang = i18n.get_current_language()
        available_langs = i18n.get_available_languages()
        
        return jsonify({
            'success': True,
            'current_language': current_lang,
            'available_languages': available_langs
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config/save', methods=['POST'])
@login_required
def save_config():
    try:
        global scan_interval, SCAN_INTERVAL, scanning_active
        data = request.json
        
        # Update scan interval if provided
        if 'scan_interval' in data:
            new_interval = int(data['scan_interval'])
            if 30 <= new_interval <= 600:  # Validate range
                scan_interval = new_interval
                SCAN_INTERVAL = new_interval
                db.set_config('scan_interval', new_interval)
        
        # Update scanning_active if provided
        if 'scanning_active' in data:
            scanning_active = bool(data['scanning_active'])
            db.set_config('scanning_active', scanning_active)
        
        # Update other config settings
        for key in ['traffic_monitoring', 'extended_logs', 'email_alerts']:
            if key in data:
                db.set_config(key, bool(data[key]))
        
        # Update rules in database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        if 'rules' in data:
            for rule_name, enabled in data['rules'].items():
                rule_map = {
                    'new_device_alert': 'new_device_detected',
                    'reconnect_alert': 'frequent_reconnect',
                    'suspicious_mac_alert': 'suspicious_mac'
                }
                
                db_rule_name = rule_map.get(rule_name, rule_name)
                cursor.execute('''
                    UPDATE rules SET enabled = ? WHERE name = ?
                ''', (1 if enabled else 0, db_rule_name))
        
        conn.commit()
        conn.close()
        
        # Reload alert engine rules
        alert_engine.reload_rules()
        
        db.add_event(
            event_type='config_updated',
            severity='info',
            description=f'System configuration updated. Scan interval: {scan_interval}s'
        )
        
        return jsonify({
            'success': True, 
            'message': 'Configuration saved successfully',
            'scan_interval': scan_interval
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/stop', methods=['POST'])
@login_required
def stop_scanning():
    try:
        # Update config - scanner loop will detect and stop
        db.set_config('scanning_active', False)
        db.add_event(
            event_type='scan_stopped',
            severity='info',
            description='Network scanning manually stopped'
        )
        return jsonify({'success': True, 'message': 'Scanning will stop after current cycle'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scanning():
    try:
        global scanner_thread, _scanner_started
        
        # Update config first
        db.set_config('scanning_active', True)
        
        # Start scanner if not already running
        if scanner_thread is None or not scanner_thread.is_alive():
            scanner_thread = threading.Thread(target=_scanner_loop, args=(app,), daemon=True)
            scanner_thread.start()
            _scanner_started = True
            
        db.add_event(
            event_type='scan_started',
            severity='info',
            description='Network scanning manually started'
        )
        return jsonify({'success': True, 'message': 'Scanning started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/rules')
@login_required
def rules_page():
    return render_template('rules.html')


@app.route('/analytics')
@login_required
def analytics_page():
    return render_template('analytics.html')


@app.route('/api/rules', methods=['GET'])
@login_required
def get_rules():
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM rules ORDER BY id DESC')
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'success': True, 'data': rules})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/add', methods=['POST'])
@login_required
def add_rule():
    try:
        data = request.json
        name = data.get('name')
        rule_type = data.get('rule_type', 'device_event')
        condition = data.get('condition')
        threshold = data.get('threshold', 1)
        severity = data.get('severity', 'medium')
        
        if not name or not condition:
            return jsonify({'success': False, 'error': 'Name and condition required'}), 400
        
        # Use smart validation
        validation_errors = smart_alert_engine.add_rule_validation({
            'name': name, 'condition': condition, 'threshold': threshold, 'severity': severity
        })
        if validation_errors:
            return jsonify({'success': False, 'error': '; '.join(validation_errors)}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO rules (name, rule_type, condition, threshold, severity, enabled)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (name, rule_type, condition, threshold, severity))
        conn.commit()
        rule_id = cursor.lastrowid
        conn.close()
        
        db.add_event(
            event_type='rule_created',
            severity='info',
            description=f'New rule created: {name}'
        )
        
        # Reload rules
        alert_engine.reload_rules()
        
        return jsonify({'success': True, 'rule_id': rule_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def delete_rule(rule_id):
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
        
        db.add_event(
            event_type='rule_deleted',
            severity='info',
            description=f'Rule {rule_id} deleted'
        )
        
        # Reload rules
        alert_engine.reload_rules()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    try:
        data = request.json
        enabled = data.get('enabled', 1)
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE rules SET enabled = ? WHERE id = ?', (enabled, rule_id))
        conn.commit()
        conn.close()
        
        # Reload rules
        alert_engine.reload_rules()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/test', methods=['POST'])
@login_required
def test_rule():
    """Test a rule against a specific device"""
    try:
        data = request.json
        rule_data = {
            'name': data.get('name'),
            'condition': data.get('condition'),
            'threshold': data.get('threshold', 1),
            'severity': data.get('severity', 'medium')
        }
        test_device_id = data.get('device_id')
        
        if not test_device_id:
            return jsonify({'success': False, 'error': 'Device ID required'}), 400
        
        result = smart_alert_engine.test_rule(rule_data, test_device_id)
        return jsonify({'success': True, 'result': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# WebSocket Event Handlers - Silent mode
@socketio.on('connect')
def handle_connect():
    """Handle client connection - silent"""
    emit('connected', {'message': 'Connected to NetWatch SIEM'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection - silent"""
    pass

@socketio.on('request_dashboard_stats')
def handle_dashboard_stats_request():
    """Handle dashboard stats request"""
    try:
        stats = db.get_dashboard_stats()
        emit('dashboard_stats_update', {
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        emit('error', {'message': f'Error fetching dashboard stats: {str(e)}'})

@socketio.on('request_device_list')
def handle_device_list_request():
    """Handle device list request"""
    try:
        devices = db.get_all_devices()
        emit('device_list_update', {
            'devices': devices,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        emit('error', {'message': f'Error fetching device list: {str(e)}'})

# MAIN ENTRY POINT

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)