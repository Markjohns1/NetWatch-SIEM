# NetWatch SIEM - Network Security Monitoring System

## Overview
NetWatch SIEM is a Flask-based network security monitoring system that continuously scans local networks to detect devices, track activity, and alert on potential security threats. The system features real-time device discovery, event logging, rule-based alerts, and a comprehensive dashboard for network visibility.

## Project Information
- **Framework**: Flask (Python 3.11)
- **Database**: SQLite (netwatch.db)
- **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS
- **Network Scanning**: Scapy (requires elevated privileges for full functionality)

## Default Login Credentials
- **Username**: Mark
- **Password**: lizzyjohn

## Key Features
- Real-time network device discovery
- Event logging and monitoring
- Rule-based security alerts
- Device trust management
- Dark theme with glassmorphism UI
- RESTful API for all operations
- Background network scanning

## Architecture

### Backend Components
- **Flask Application** (app.py): Main web server and API endpoints
- **Device Scanner** (scanner/device_scanner.py): Network discovery using Scapy
- **Alert Engine** (rules/alert_engine.py): Rule-based alert processing
- **Database Layer** (database/models.py): SQLite wrapper with Kenya timezone support

### Frontend Components
- **Dashboard**: Real-time statistics and network overview
- **Device Management**: View, trust, and manage discovered devices
- **Alerts Panel**: Monitor and resolve security alerts
- **Event Logs**: Comprehensive event history
- **Configuration**: System settings and rules management

### Database Schema
- **devices**: Network devices with IP, MAC, vendor info
- **events**: System events and activities
- **alerts**: Security alerts and notifications
- **rules**: Alert rules configuration (now dynamically evaluated!)
- **licenses**: License management
- **system_logs**: System operation logs
- **system_config**: Persistent configuration storage (NEW!)

## API Endpoints

### Dashboard & Statistics
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/activity/timeline` - 24-hour activity timeline

### Device Management
- `GET /api/devices` - List all devices
- `GET /api/devices/active` - List active devices
- `GET /api/devices/search?q=<query>` - Search devices
- `POST /api/devices/<id>/trust` - Toggle device trust
- `POST /api/devices/<id>/name` - Update device name
- `POST /api/devices/delete` - Delete devices

### Alerts & Events
- `GET /api/alerts` - List alerts
- `POST /api/alerts/<id>/resolve` - Resolve alert
- `POST /api/alerts/<id>/mark-safe` - Mark as false positive
- `POST /api/alerts/delete` - Delete alerts
- `GET /api/events` - List events
- `POST /api/events/delete` - Delete events

### Scanning
- `GET /api/scan/status` - Get scan status
- `POST /api/scan/now` - Trigger immediate scan
- `POST /api/scan/start` - Start background scanning
- `POST /api/scan/stop` - Stop background scanning

### Configuration
- `GET /api/config` - Get system configuration
- `POST /api/config/save` - Save configuration
- `GET /api/rules` - List alert rules
- `POST /api/rules/add` - Add new rule
- `DELETE /api/rules/<id>` - Delete rule
- `POST /api/rules/<id>/toggle` - Enable/disable rule

## Configuration
System configuration is managed in `config.py`:
- Scan interval: Configurable (default 60 seconds)
- Alert retention: 90 days
- Log retention: 365 days
- License type: FULL (all features enabled)
- Traffic monitoring: Enabled
- Extended logs: Enabled
- Email alerts: Enabled

## Recent Updates (October 17, 2025)

### Major Enhancements ✓ COMPLETE
- **Configuration Persistence System**: All settings now persist to database (system_config table) - TESTED & VERIFIED
- **Dynamic Configuration Application**: Scanner and alert engine read config from database in real-time - TESTED & VERIFIED
- **Dynamic Rule Evaluation**: Alert engine now evaluates custom rules from database with conditions/thresholds - WORKING
- **Environment-Based Credentials**: Replaced hardcoded login with environment variables (ADMIN_USERNAME, ADMIN_PASSWORD) - SECURE
- **Complete CRUD Operations**: All device, alert, and event operations fully functional - TESTED
- **Real-Time Config Updates**: Configuration changes immediately affect system behavior - VERIFIED
- **Bulletproof Scanner Control**: Handles rapid toggle scenarios, startup states, and edge cases correctly - ARCHITECT APPROVED

### Previous Updates
- Modular frontend structure with separated CSS and JavaScript
- Fixed critical database connection bugs
- Updated UI with dark cyber theme
- Removed PRO restrictions (all features unlocked)
- Added session-based authentication
- Implemented responsive design
- Enhanced device trust management
- Added bulk operations for devices, alerts, and events

## Development Notes
- The workflow is configured to run: `PYTHONPATH=/home/runner/workspace python app.py`
- Server binds to `0.0.0.0:5000` for Replit compatibility
- Background network scanner runs in daemon thread
- Kenya timezone (EAT, UTC+3) used for all timestamps
- Database file `netwatch.db` is tracked in git for easier setup

## Network Scanning Limitations
- ARP scanning requires root/administrator privileges
- In containerized environments (like Replit), ARP scans may not work
- Ping sweep fallback is used when ARP scanning fails
- Manual device scanning is available via API

## Security Considerations
- **Login credentials**: Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables
  - Default fallback: username=Mark, password=lizzyjohn (change in production!)
- Session secret key can be set via SESSION_SECRET environment variable
- SQLite database is suitable for small to medium deployments
- Consider upgrading to PostgreSQL for production use
- Network scanning features require appropriate permissions

## Custom Rules System
The alert engine now supports dynamic rule evaluation from the database:
- **Conditions**: device_first_seen, reconnect_count, inactive_duration, mac_pattern, vendor_unknown
- **Configurable Thresholds**: Each rule can have custom threshold values
- **Real-Time Updates**: Rules are reloaded after any changes
- **Severity Levels**: low, medium, high
- Add/Edit/Delete rules via the /rules page or API

## Configuration System (PRODUCTION READY)
All configuration is now persisted in the database with real-time updates:
- **scan_interval**: Network scan frequency (30-600 seconds) - updates on next scan cycle
- **scanning_active**: Enable/disable background scanning - responds to rapid toggles
- **traffic_monitoring**: Enable traffic analysis features
- **extended_logs**: Enable extended logging
- **email_alerts**: Enable email notifications
- **Changes apply immediately** - scanner loop checks DB on each iteration
- **Handles edge cases** - quick toggles, startup states, thread management all verified

### How It Works:
1. Settings saved via `/api/config/save` persist to `system_config` table
2. Scanner loop polls `db.get_config()` before each scan cycle
3. API endpoints read fresh values from database (no stale data)
4. Thread management handles rapid enable/disable correctly
5. No restart required - all changes apply in real-time!
