from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit, disconnect
from functools import wraps
from database.models import Database, get_kenya_time
from scanner.device_scanner import DeviceScanner
from rules.alert_engine import AlertEngine
from rules.smart_alert_engine import SmartAlertEngine
from flask.signals import appcontext_pushed
from i18n import I18nManager
from security import SecurityManager, require_auth, validate_input, sanitize_input
from security.schemas import *
from models import UserManager
from monitoring import AdvancedNetworkScanner, TrafficAnalyzer
import threading
import time
import asyncio
from datetime import datetime, timedelta
import os
from scanner.device_scanner import Colors
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'netwatch-siem-secret-key-2024')
app.logger.setLevel(logging.ERROR)

# Initialize security manager
security_manager = SecurityManager(app)

socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    logger=False, 
    engineio_logger=False,
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=10000000,
    allow_upgrades=True,
    transports=['websocket', 'polling'],
    engineio_logger_level='ERROR'
)

def safe_emit(event, data, **kwargs):
    try:
        socketio.emit(event, data, **kwargs)
    except Exception as e:
        pass

active_clients = set()

i18n = I18nManager()
i18n.init_app(app)

VALID_USERNAME = os.environ.get('ADMIN_USERNAME', 'Mark')
VALID_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'lizzyjohn')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


db = Database()

# Initialize user manager
user_manager = UserManager(db)

# Initialize enhanced monitoring systems
advanced_scanner = AdvancedNetworkScanner(db)
traffic_analyzer = TrafficAnalyzer(db)

db.set_config('scanning_active', True)
print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Auto-enabling network scanner...")

scanner = DeviceScanner(db, verbose=False, show_banner=True)
smart_alert_engine = SmartAlertEngine(db)
alert_engine = AlertEngine(db)

scan_interval = db.get_config('scan_interval') or 60
scanning_active = db.get_config('scanning_active') or False
SCAN_INTERVAL = scan_interval

scanner_thread = None
_scanner_started = False


def _scanner_loop(app):
    with app.app_context():
        global SCAN_INTERVAL
        previous_devices = set()
        
        while True:
            current_scanning_active = db.get_config('scanning_active')
            if current_scanning_active is None:
                current_scanning_active = True
                
            if not current_scanning_active:
                break
            
            try:
                current_interval = db.get_config('scan_interval') or 60
                SCAN_INTERVAL = current_interval
                
                # Use enhanced scanner for better device detection
                try:
                    devices = asyncio.run(advanced_scanner.comprehensive_network_scan())
                except Exception as e:
                    print(f"{Colors.YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Enhanced scan failed, falling back to basic scan: {e}")
                    devices = scanner.scan_network()

                current_devices = set()
                device_status_changes = []
                
                for device_dict in devices:
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    # Get existing device info including device_name
                    cursor.execute('SELECT id, status, device_name, hostname, vendor FROM devices WHERE mac_address = ?', (device_dict['mac'],))
                    result = cursor.fetchone()

                    if result:
                        device_id, old_status, existing_name, existing_hostname, existing_vendor = result
                        current_devices.add(device_id)
                        
                        # Update device information while preserving user-set name
                        kenya_time = get_kenya_time()
                        cursor.execute('''
                            UPDATE devices 
                            SET ip_address = ?, hostname = ?, vendor = ?, status = 'online', last_seen = ?
                            WHERE id = ?
                        ''', (
                            device_dict['ip'], 
                            device_dict.get('hostname') or existing_hostname,
                            device_dict.get('vendor') or existing_vendor,
                            kenya_time,
                            device_id
                        ))
                        conn.commit()
                        
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
                        # Add new device
                        device_id = db.add_device(
                            device_dict['ip'], 
                            device_dict['mac'], 
                            device_dict.get('hostname'),
                            device_dict.get('vendor')
                        )
                        if device_id:
                            current_devices.add(device_id)
                            device_status_changes.append({
                                'device_id': device_id,
                                'ip': device_dict['ip'],
                                'mac': device_dict['mac'],
                                'status': 'online',
                                'change': 'new_device'
                            })
                            print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_CYAN}[NEW]{Colors.RESET} {device_dict['ip']} ({device_dict['mac']}) - {device_dict.get('vendor', 'Unknown')}")

                    conn.close()

                offline_devices = previous_devices - current_devices
                for device_id in offline_devices:
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('SELECT ip_address, mac_address FROM devices WHERE id = ?', (device_id,))
                    result = cursor.fetchone()
                    if result:
                        ip, mac = result
                        
                        db.update_device_status(device_id, 'offline')
                        
                        device_status_changes.append({
                            'device_id': device_id,
                            'ip': ip,
                            'mac': mac,
                            'status': 'offline',
                            'change': 'went_offline'
                        })
                        print(f"{Colors.RED}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.RED}[OFFLINE]{Colors.RESET} {ip} ({mac})")
                    conn.close()

                if device_status_changes:
                    safe_emit('device_status_update', {
                        'changes': device_status_changes,
                        'timestamp': datetime.now().isoformat(),
                        'total_devices': len(current_devices)
                    })
                
                stats = db.get_dashboard_stats()
                safe_emit('dashboard_stats_update', {
                    'stats': stats,
                    'timestamp': datetime.now().isoformat()
                })

                previous_devices = current_devices

                smart_alert_engine.run_smart_periodic_checks()

            except Exception as e:
                print(f"{Colors.RED}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.RED}[ERROR]{Colors.RESET} Scanner error: {e}")

            time.sleep(SCAN_INTERVAL)

def start_background_scanner():
    global scanner_thread, _scanner_started
    
    if _scanner_started:
        return
    
    _scanner_started = True
    
    scanning_enabled = db.get_config('scanning_active')
    if scanning_enabled is None:
        scanning_enabled = True
        db.set_config('scanning_active', True)
    
    if scanning_enabled:
        scanner_thread = threading.Thread(target=_scanner_loop, args=(app,), daemon=True)
        scanner_thread.start()
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}[OK] Background scanning: ACTIVE{Colors.RESET}\n")
    else:
        print(f"{Colors.YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.YELLOW}⚠ Background scanning: DISABLED{Colors.RESET}\n")


def _on_appcontext_pushed(sender, **extra):
    start_background_scanner()

appcontext_pushed.connect(_on_appcontext_pushed, app)


@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr
    
    # Check if IP is locked out
    if security_manager.is_locked_out(client_ip):
        return render_template('login.html', error='Too many failed attempts. Please try again later.')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Sanitize input
        username = sanitize_input(username)
        
        # Validate input
        if not username or not password:
            security_manager.record_failed_attempt(client_ip)
            return render_template('login.html', error='Username and password are required')
        
        if len(username) > 50 or len(password) > 100:
            security_manager.record_failed_attempt(client_ip)
            return render_template('login.html', error='Invalid input length')
        
        # Authenticate user using user manager
        auth_result = user_manager.authenticate_user(username, password, client_ip)
        
        if auth_result['success']:
            user = auth_result['user']
            
            # Clear failed attempts on successful login
            security_manager.clear_failed_attempts(client_ip)
            
            # Create secure session
            session_token = user_manager.create_session(user['id'], client_ip, request.headers.get('User-Agent'))
            
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_admin'] = user['role'] == 'admin'
            session['last_activity'] = datetime.now().isoformat()
            session['csrf_token'] = security_manager.generate_csrf_token()
            session['session_token'] = session_token
            
            return redirect(url_for('index'))
        else:
            security_manager.record_failed_attempt(client_ip)
            return render_template('login.html', error=auth_result['error'])
    
    if 'logged_in' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    # Log logout event
    if 'username' in session:
        db.add_event(
            event_type='user_logout',
            severity='info',
            description=f'User {session["username"]} logged out'
        )
    
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
            devices = db.get_all_devices()
        else:
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
@require_auth
def toggle_device_trust(device_id):
    try:
        data = request.json or {}
        data = sanitize_input(data)
        
        # Validate input
        errors = validate_input(data, DEVICE_TRUST_SCHEMA)
        if errors:
            return jsonify({'success': False, 'error': '; '.join(errors)}), 400
        
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
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
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
        
        return jsonify({'success': True, 'data': timeline_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analytics/device-trends')
@login_required
def get_device_trends():
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
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
        
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM devices
            GROUP BY status
        ''')
        
        status_distribution = [{'status': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
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
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
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
        
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            WHERE datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY alert_type
            ORDER BY count DESC
        ''')
        
        alert_types = [{'type': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
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
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
        online_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM devices WHERE is_trusted = 1")
        trusted_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
        active_alerts = cursor.fetchone()[0]
        
        if total_devices > 0:
            online_ratio = online_devices / total_devices
            trusted_ratio = trusted_devices / total_devices
            alert_ratio = min(active_alerts / total_devices, 1.0)
            
            health_score = (
                online_ratio * 40 +
                trusted_ratio * 30 +
                (1 - alert_ratio) * 30
            ) * 100
        else:
            health_score = 100
        
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
            deleted_count = db.delete_events()
        
        return jsonify({'success': True, 'deleted_count': deleted_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/timezone/info')
@login_required
def get_timezone_info():
    kenya_tz = datetime.timezone(timedelta(hours=3))
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
        
        if 'scan_interval' in data:
            new_interval = int(data['scan_interval'])
            if 30 <= new_interval <= 600:
                scan_interval = new_interval
                SCAN_INTERVAL = new_interval
                db.set_config('scan_interval', new_interval)
        
        if 'scanning_active' in data:
            scanning_active = bool(data['scanning_active'])
            db.set_config('scanning_active', scanning_active)
        
        for key in ['traffic_monitoring', 'extended_logs', 'email_alerts']:
            if key in data:
                db.set_config(key, bool(data[key]))
        
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
        
        db.set_config('scanning_active', True)
        
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


@app.route('/users')
@require_auth
def users_page():
    return render_template('users.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'viewer')
        
        # Validate input
        if not username or len(username) < 3:
            return render_template('register.html', error='Username must be at least 3 characters')
        
        if not email or '@' not in email:
            return render_template('register.html', error='Valid email address required')
        
        if not password or len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        # Register user
        result = user_manager.register_user(username, email, password, role)
        
        if result['success']:
            return render_template('login.html', success='Registration successful! Please log in.')
        else:
            return render_template('register.html', error=result['error'])
    
    return render_template('register.html')


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
        
        alert_engine.reload_rules()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/rules/<int:rule_id>', methods=['PUT'])
@login_required
def update_rule(rule_id):
    """Update an existing rule"""
    try:
        data = request.json
        name = data.get('name')
        condition = data.get('condition')
        threshold = data.get('threshold')
        severity = data.get('severity')
        
        if not name or not condition:
            return jsonify({'success': False, 'error': 'Name and condition required'}), 400
        
        # Validate threshold
        validation_errors = smart_alert_engine.add_rule_validation({
            'name': name, 'condition': condition, 'threshold': threshold, 'severity': severity
        })
        if validation_errors:
            return jsonify({'success': False, 'error': '; '.join(validation_errors)}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if rule exists
        cursor.execute('SELECT id FROM rules WHERE id = ?', (rule_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Rule not found'}), 404
        
        # Update rule
        cursor.execute('''
            UPDATE rules 
            SET name = ?, condition = ?, threshold = ?, severity = ?
            WHERE id = ?
        ''', (name, condition, threshold, severity, rule_id))
        
        conn.commit()
        conn.close()
        
        db.add_event(
            event_type='rule_updated',
            severity='info',
            description=f'Rule updated: {name}'
        )
        
        alert_engine.reload_rules()
        
        return jsonify({'success': True, 'rule_id': rule_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rules/conditions', methods=['GET'])
@login_required
def get_condition_metadata():
    """Return metadata about all available conditions for the frontend"""
    try:
        from rules.condition_metadata import CONDITION_METADATA
        return jsonify({
            'success': True,
            'data': CONDITION_METADATA
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/validate', methods=['POST'])
@login_required
def validate_rule_threshold():
    """Validate a threshold value for a given condition (frontend use)"""
    try:
        from rules.condition_metadata import validate_threshold_for_condition
        
        data = request.json
        condition = data.get('condition')
        threshold = data.get('threshold')
        
        is_valid, message = validate_threshold_for_condition(condition, threshold)
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': message
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/rules/test', methods=['POST'])
@login_required
def test_rule():
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


# User Management API Endpoints
@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    try:
        users = user_manager.get_all_users()
        return jsonify({'success': True, 'data': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users', methods=['POST'])
@require_auth
def create_user():
    try:
        data = request.json or {}
        data = sanitize_input(data)
        
        # Validate input
        errors = validate_input(data, {
            'username': {'type': 'str', 'required': True, 'min_length': 3, 'max_length': 50},
            'email': {'type': 'str', 'required': True, 'max_length': 100},
            'password': {'type': 'str', 'required': True, 'min_length': 8},
            'role': {'type': 'str', 'required': True}
        })
        
        if errors:
            return jsonify({'success': False, 'error': '; '.join(errors)}), 400
        
        result = user_manager.register_user(
            data['username'],
            data['email'],
            data['password'],
            data['role']
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/<int:user_id>/status', methods=['PUT'])
@require_auth
def update_user_status(user_id):
    try:
        data = request.json or {}
        is_active = data.get('is_active', True)
        
        if is_active:
            # Reactivate user
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
        else:
            # Deactivate user
            user_manager.deactivate_user(user_id)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/users/activity', methods=['GET'])
@require_auth
def get_user_activity():
    try:
        limit = request.args.get('limit', 100, type=int)
        activity = user_manager.get_user_activity(limit=limit)
        return jsonify({'success': True, 'data': activity})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@socketio.on('connect')
def handle_connect():
    try:
        client_sid = request.sid
        active_clients.add(client_sid)
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Client connected: {client_sid}")
        emit('connected', {'message': 'Connected to NetWatch SIEM'}, skip_errors=True)
    except Exception:
        pass

@socketio.on('disconnect')
def handle_disconnect():
    try:
        client_sid = request.sid
        if client_sid in active_clients:
            active_clients.remove(client_sid)
        print(f"{Colors.YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Client disconnected: {client_sid}")
    except Exception:
        pass

@socketio.on('request_dashboard_stats')
def handle_dashboard_stats_request():
    try:
        stats = db.get_dashboard_stats()
        if stats:
            emit('dashboard_stats_update', {
                'stats': stats,
                'timestamp': datetime.now().isoformat()
            }, skip_errors=True)
    except Exception:
        pass

@socketio.on('request_device_list')
def handle_device_list_request():
    try:
        devices = db.get_all_devices()
        if devices is not None:
            emit('device_list_update', {
                'devices': devices,
                'timestamp': datetime.now().isoformat()
            }, skip_errors=True)
    except Exception:
        pass


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)