NetWatch SIEM - Network Monitoring System
NetWatch SIEM is a Flask-based network security monitoring system that continuously scans local networks to detect devices, track activity, and alert on potential security threats. The system features real-time device discovery, event logging, rule-based alerts, and a comprehensive dashboard for network visibility. It is lightweight, works offline, and uses SQLite for data storage.
Project Information
Framework: Flask (Python 3.11)
Database: SQLite (netwatch.db)
Frontend: HTML5, Vanilla JavaScript, Tailwind CSS
Network Scanning: Scapy (requires elevated privileges)
Design: Service-oriented modular architecture
Default Login Credentials
Username: Mark
Password: lizzyjohn
Note: Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables for production use. The session secret key can be set via SESSION_SECRET environment variable.
Key Features
Real-time network device discovery using ARP scanning and MAC vendor identification
Event logging and comprehensive monitoring
Rule-based security alerts with dynamic evaluation
Device trust management to reduce noise
Dark cyber theme with glassmorphism UI effects
RESTful API for all operations
Background network scanning in separate thread
Configuration persistence with real-time updates
Custom alert rules with configurable thresholds
Bulk operations for devices, alerts, and events
Responsive design with mobile-friendly interface
System Architecture
Backend Components:
Flask Application (app.py): Main web server with session-based authentication and API endpoints
Device Scanner (scanner/device_scanner.py): Network discovery using Scapy for ARP scanning, ping sweep fallback, MAC vendor identification. Runs in background daemon thread.
Alert Engine (rules/alert_engine.py): Processes events and triggers alerts based on database rules with dynamic evaluation of conditions and thresholds
Database Layer (database/models.py): SQLite wrapper with Kenya timezone (EAT, UTC+3) support, dictionary-style access, and thread-safe connections
Frontend Components:
Dashboard: Real-time statistics and network overview with activity timeline
Device Management: View, search, trust, and manage discovered devices
Alerts Panel: Monitor and resolve security alerts, mark false positives
Event Logs: Comprehensive event history with filtering
Configuration: System settings, scan intervals, and rules management
Rules Manager: Add, edit, delete, and toggle custom alert rules
Database Schema:
devices: Network devices with IP, MAC, hostname, vendor, trust status, risk score
events: System events and activities with timestamps
alerts: Security alerts and notifications with resolution tracking
rules: Alert rules configuration with dynamic evaluation support
licenses: License management (FULL license, all features enabled)
system_logs: System operation logs
system_config: Persistent configuration storage for real-time updates
Security and Monitoring Features
Device Discovery: ARP scanning with automatic vendor identification from MAC addresses
Alert Types: New devices, frequent reconnections, suspicious MAC addresses, device inactivity, IP changes, unknown vendors
Trust Management: Mark devices as trusted to filter out known devices from alerts
Custom Rules: Create dynamic rules with conditions (device_first_seen, reconnect_count, inactive_duration, mac_pattern, vendor_unknown, ip_changed)
Configurable Thresholds: Each rule supports custom threshold values
Severity Levels: Low, medium, high classifications for prioritization
Real-Time Rule Updates: Rules reload automatically after changes
API Endpoints
Dashboard and Statistics:
GET /api/dashboard/stats - Dashboard statistics (total devices, active devices, alerts, trusted devices, new today)
GET /api/activity/timeline - Activity data grouped by minute for last 2 hours
Device Management:
GET /api/devices - List all devices
GET /api/devices/active - List only active devices
GET /api/devices/search?q=query - Search devices by IP, MAC, name, hostname, or vendor
POST /api/devices/id/trust - Toggle device trust status
POST /api/devices/id/name - Update device name
POST /api/devices/delete - Delete multiple devices by ID
Alerts and Events:
GET /api/alerts - List alerts with optional limit parameter
POST /api/alerts/id/resolve - Resolve specific alert
POST /api/alerts/id/mark-safe - Mark alert as false positive
POST /api/alerts/delete - Delete multiple alerts or all resolved alerts
GET /api/events - List events with optional limit parameter
POST /api/events/delete - Delete multiple events or all events
Network Scanning:
GET /api/scan/status - Get current scan status and interval
POST /api/scan/now - Trigger immediate network scan
POST /api/scan/start - Start background scanning
POST /api/scan/stop - Stop background scanning
Configuration and Rules:
GET /api/config - Get system configuration
POST /api/config/save - Save configuration changes
GET /api/rules - List all alert rules
POST /api/rules/add - Add new custom rule
DELETE /api/rules/id - Delete specific rule
POST /api/rules/id/toggle - Enable or disable rule
Utilities:
GET /api/timezone/info - Get timezone information (Africa/Nairobi, UTC+3)
Response Format: All API endpoints return JSON with success boolean, data payload for successful requests, and error messages for failures.
Configuration System
All configuration persists to database with real-time application. Settings saved via /api/config/save are immediately effective without restart.
Available Settings:
scan_interval: Network scan frequency in seconds (range: 30-600, default: 60)
scanning_active: Enable or disable background scanning (boolean)
traffic_monitoring: Enable traffic analysis features (boolean)
extended_logs: Enable extended logging (boolean)
email_alerts: Enable email notifications (boolean)
alert_retention_days: Days to retain alerts (default: 90)
log_retention_days: Days to retain logs (default: 365)
Configuration Behavior:
Settings persist to system_config table in database
Scanner loop polls database before each scan cycle
Changes apply immediately without application restart
Handles rapid toggle scenarios correctly
API endpoints read fresh values from database
Thread management handles enable/disable correctly
Custom Rules System
The alert engine supports dynamic rule evaluation from database with the following features:
Rule Conditions:
device_first_seen: Triggers when device is first detected (threshold in days)
reconnect_count: Triggers when device reconnection count exceeds threshold
inactive_duration: Triggers when device inactive for threshold seconds
mac_pattern: Detects suspicious MAC address patterns
vendor_unknown: Triggers for devices with unknown vendors
ip_changed: Detects IP address changes for same device
Rule Properties:
name: Unique rule identifier
rule_type: Type of rule (device_event, traffic_event, etc.)
condition: The condition to evaluate
threshold: Numeric threshold for condition
severity: Alert severity (low, medium, high)
enabled: Rule active status (boolean)
Rule Management:
Add, edit, delete rules via /rules page or API
Rules reload automatically after changes
Each rule evaluated independently
Prevents duplicate alerts for same device and rule
Supports custom metadata for detailed tracking
Recent Updates (October 17, 2025)
Configuration Persistence System: All settings persist to database via system_config table. Tested and verified working.
Dynamic Configuration Application: Scanner and alert engine read configuration from database in real-time. Changes apply immediately.
Dynamic Rule Evaluation: Alert engine evaluates custom rules from database with configurable conditions and thresholds. Fully functional.
Environment-Based Credentials: Login credentials now use environment variables (ADMIN_USERNAME, ADMIN_PASSWORD) with secure fallback.
Complete CRUD Operations: All device, alert, and event operations fully functional and tested.
Bulletproof Scanner Control: Handles rapid toggle scenarios, startup states, and edge cases correctly. Architect approved.
Modular Frontend: Separated CSS (main.css, cyber-theme.css) and JavaScript modules (dashboard.js, devices.js, alerts.js).
Database Connection Fixes: Resolved critical bugs in alert engine and database layer.
UI Enhancements: Updated dark cyber theme with glassmorphism effects, color-coded status indicators, and responsive design.
Feature Unlocking: Removed PRO restrictions. All features now available in FULL license mode.
Bulk Operations: Added support for bulk deletion of devices, alerts, and events.
Enhanced Trust Management: Improved device trust workflow with better UI feedback.
Development Notes
Server binds to 0.0.0.0:5000 for broad compatibility including Replit
Background network scanner runs in daemon thread for automatic cleanup
Kenya timezone (EAT, UTC+3) used for all timestamps
Database file netwatch.db tracked in git for easier development setup
Workflow configured with PYTHONPATH for module imports
Flask debug mode disabled for production-like behavior
All features enabled by default (FULL license mode)
Network Scanning Limitations
ARP scanning requires root or administrator privileges for raw socket access
In containerized environments (Replit, Docker), ARP scans may not work due to network restrictions
Ping sweep fallback used automatically when ARP scanning fails
Manual device scanning available via API as alternative
Network interface detection attempts to find best active interface automatically
Security Considerations
Login credentials should use environment variables in production (ADMIN_USERNAME, ADMIN_PASSWORD)
Default credentials (Mark/lizzyjohn) are for development only
Session secret key configurable via SESSION_SECRET environment variable
SQLite suitable for small to medium deployments (up to 1000 devices)
Consider PostgreSQL for larger production deployments
Network scanning features require appropriate system permissions
Session-based authentication protects all routes except login
Database uses thread-safe connections for concurrent access
Input validation on all API endpoints prevents injection attacks
Dependencies
Python Libraries:
Flask: Web framework and routing
Scapy: Network packet manipulation and ARP scanning
psutil: System and network interface information
sqlite3: Database operations (standard library)
Frontend Libraries:
Tailwind CSS: Utility-first styling framework
Feather Icons: Icon system for UI elements
Chart.js: Data visualizations and activity timeline
Vanilla JavaScript: No heavy frameworks, minimal dependencies
Network Requirements:
Local network access required for scanning
Elevated privileges may be needed for ARP scanning
Optional: Email server for alert notifications
Infrastructure: Offline operation, all data local
File Structure
app.py: Main Flask application with routes and API
config.py: Configuration management with feature flags
database/models.py: SQLite database wrapper with timezone support
scanner/device_scanner.py: Network scanning and device discovery
rules/alert_engine.py: Alert processing and rule evaluation
templates/: HTML templates (base.html, dashboard.html, devices.html, alerts.html, logs.html, config.html, rules.html, login.html)
static/css/: Stylesheets (main.css, cyber-theme.css)
static/js/: JavaScript modules (dashboard.js, devices.js, alerts.js)
netwatch.db: SQLite database file
Future Enhancements
Email notification system for critical alerts
Traffic monitoring and analysis features
Network topology mapping and visualization
Integration with external threat intelligence feeds
Export functionality for reports and compliance
Multi-user support with role-based access control
API authentication with tokens for external integrations
Performance optimization for large networks (1000+ devices)
Real-time WebSocket updates for live dashboard
Mobile application for on-the-go monitoring