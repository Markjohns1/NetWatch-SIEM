from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from functools import wraps
from database.models import Database
from scanner.device_scanner import DeviceScanner
from rules.alert_engine import AlertEngine
from flask.signals import appcontext_pushed
import threading
import time
from datetime import datetime
import os

#app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'netwatch-siem-secret-key-2024')

VALID_USERNAME = 'Mark'
VALID_PASSWORD = 'lizzyjohn'


#login protection
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#db setup
db = Database()
scanner = DeviceScanner(db)
alert_engine = AlertEngine(db)

scan_interval = 60
scanning_active = False


# background scanner setup
SCAN_INTERVAL = 60  
scanner_thread = None
_scanner_started = False  # Track if scanner started once


def _scanner_loop(app):
    """
    Runs the network scanner in a background thread.
    Must run inside app context so DB access works.
    """
    with app.app_context():
        global scanning_active
        scanning_active = True
        while scanning_active:
            try:
                # Scan network devices
                devices = scanner.scan_network()
                app.logger.info(f"Scanner found {len(devices)} devices at {datetime.now()}")

                # Process alerts for each detected device
                for device_dict in devices:
                    conn = db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('SELECT id FROM devices WHERE mac_address = ?', (device_dict['mac'],))
                    result = cursor.fetchone()

                    if result:
                        device_id = result[0]
                        alert_engine.process_device_alerts(device_id)

                    conn.close()

                # Run periodic rule checks
                alert_engine.run_periodic_checks()

            except Exception as e:
                app.logger.exception(f"Scanner error: {e}")

            time.sleep(SCAN_INTERVAL)


def start_background_scanner():
    """
    Starts the background scanner thread safely once.
    """
    global scanner_thread, _scanner_started
    if _scanner_started:
        return  # Already started once
    scanner_thread = threading.Thread(target=_scanner_loop, args=(app,), daemon=True)
    scanner_thread.start()
    _scanner_started = True
    app.logger.info("Background scanner started.")


def _on_appcontext_pushed(sender, **extra):
    start_background_scanner()

# Connect the signal to start scanner when app context is pushed
appcontext_pushed.connect(_on_appcontext_pushed, app)


# ==============================
# ROUTES
# ==============================

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
    global scanning_active
    return jsonify({'success': True, 'scanning': scanning_active, 'interval': scan_interval})


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
                alert_engine.process_device_alerts(device_id)
            
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
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                COUNT(*) as count
            FROM events
            WHERE datetime(timestamp) >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''')
        
        timeline_data = [{'time': row[0], 'count': row[1]} for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'data': timeline_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config')
@login_required
def get_config():
    try:
        from config import Config
        
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT name, enabled FROM rules')
        rules_data = cursor.fetchall()
        rules_dict = {row['name']: bool(row['enabled']) for row in rules_data}
        
        config_data = {
            'scan_interval': scan_interval,
            'scanning_active': scanning_active,
            'license_type': Config.LICENSE_TYPE,
            'traffic_monitoring': Config.TRAFFIC_MONITORING,
            'extended_logs': Config.EXTENDED_LOGS,
            'email_alerts': Config.EMAIL_ALERTS,
            'rules': {
                'new_device_alert': rules_dict.get('new_device_detected', True),
                'reconnect_alert': rules_dict.get('frequent_reconnect', True),
                'suspicious_mac_alert': rules_dict.get('suspicious_mac', True),
                'traffic_monitoring': Config.TRAFFIC_MONITORING,
                'advanced_logging': Config.EXTENDED_LOGS
            }
        }
        
        conn.close()
        
        return jsonify({'success': True, 'data': config_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add these new routes to your existing app.py file
# Insert them before the "# MAIN ENTRY POINT" section

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


# Add these UPDATED routes to your app.py
# Replace the existing versions if they exist

@app.route('/api/config/save', methods=['POST'])
@login_required
def save_config():
    try:
        global scan_interval, SCAN_INTERVAL
        from config import Config
        data = request.json
        
        # Update scan interval if provided
        if 'scan_interval' in data:
            new_interval = int(data['scan_interval'])
            if 30 <= new_interval <= 600:  # Validate range
                scan_interval = new_interval
                SCAN_INTERVAL = new_interval
                print(f"Scan interval updated to {new_interval} seconds")
        
        # Update config in database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Update rules
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
        global scanning_active
        scanning_active = False
        db.add_event(
            event_type='scan_stopped',
            severity='info',
            description='Network scanning manually stopped'
        )
        return jsonify({'success': True, 'message': 'Scanning stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scanning():
    try:
        global scanning_active
        if not scanning_active:
            scanning_active = True
            start_background_scanner()
            db.add_event(
                event_type='scan_started',
                severity='info',
                description='Network scanning manually started'
            )
        return jsonify({'success': True, 'message': 'Scanning started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# Add this route with the other page routes

@app.route('/rules')
@login_required
def rules_page():
    return render_template('rules.html')


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
# ==============================
# MAIN ENTRY POINT
# ==============================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)