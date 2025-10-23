NetWatch SIEM - Official Documentation
========================================
Creator: JOHN O. MARK

Overview
--------

NetWatch SIEM is an enterprise-grade Flask-based Security Information and Event Management (SIEM) system designed for comprehensive network surveillance, advanced threat detection, and real-time security monitoring. The system provides deep visibility into network activity through multi-method device discovery, intelligent threat analysis, and comprehensive security event management.


Key Capabilities

• Advanced Multi-Method Device Discovery - Comprehensive network scanning using ARP, ping sweep, port scanning, passive discovery, and traffic analysis
• Real-Time Traffic Analysis - Deep packet inspection with threat detection, anomaly analysis, and connection tracking
• Enterprise Security Features - Multi-user authentication, role-based access control, and secure session management
• Smart Alert Engine - Advanced rule processing with false positive elimination, context-aware evaluation, and machine learning
• Intelligent Threat Detection - Real-time detection of port scanning, brute force attacks, DDoS, and suspicious network behavior
• Comprehensive User Management - Secure user registration, role assignment, and activity monitoring
• Advanced Analytics Dashboard - Real-time network health metrics, device trends, threat patterns, and security analytics
• International Support - Multi-language interface (English, Spanish, French, German, Chinese)
• Rule Testing & Validation - Live rule validation against real devices with comprehensive testing framework
• RESTful API - Complete programmatic access with secure authentication and input validation
• Performance Optimization - Advanced caching, database optimization, and scalable architecture
• Offline Operation - Fully functional without internet connectivity with local data storage


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Technical Specifications
------------------------

Technology Stack

Backend Framework    : Flask (Python 3.11) with async support
Database            : SQLite 3 (netwatch.db) with optimized queries
Frontend            : HTML5, Vanilla JavaScript, Tailwind CSS (responsive design)
Network Scanning    : Scapy, Nmap, psutil (multi-method discovery)
Traffic Analysis    : Real-time packet capture and analysis
Security            : PBKDF2 password hashing, session management, input validation
Analytics Engine    : Chart.js for data visualization with real-time updates
Internationalization: Custom i18n system with JSON translations
Architecture        : Service-oriented modular design with advanced monitoring
Caching             : In-memory caching with TTL support
Threat Detection    : Machine learning-based anomaly detection


System Requirements

• Python 3.11 or higher
• Root/Administrator privileges (for advanced network scanning and packet capture)
• Local network access with packet capture capabilities
• 100MB minimum disk space (for logs, cache, and database)
• 512MB RAM minimum (1GB recommended for large networks)
• Network interface with promiscuous mode support (for traffic analysis)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Installation & Setup
--------------------

Quick Start

1. Clone the repository
   
   git clone <repository-url>
   cd netwatch-siem

2. Install dependencies
   
   pip install -r requirements.txt

3. Configure environment variables (Production)
   
   export ADMIN_USERNAME="your_username"
   export ADMIN_PASSWORD="your_secure_password"
   export SESSION_SECRET="your_secret_key"

4. Run the application
   
   sudo python app.py

   Note: sudo required for network scanning

5. Access the dashboard
   
   Navigate to http://localhost:5000
   Default admin credentials: admin / NetWatch2024! (change immediately)
   
   For new installations, register additional users at /register


Environment Variables

ADMIN_USERNAME  : Admin login username (default: Mark)
ADMIN_PASSWORD  : Admin login password (default: lizzyjohn)
SESSION_SECRET  : Flask session encryption key (auto-generated)

⚠️  WARNING: Always configure custom credentials for production deployments.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Enhanced Features (Version 3.0)
-------------------------------

Multi-User Authentication System

• Secure User Registration - PBKDF2 password hashing with salt
• Role-Based Access Control - Admin, Operator, Analyst, Viewer roles
• Session Management - Secure session tokens with expiration
• User Activity Logging - Comprehensive audit trail
• Brute Force Protection - Account lockout after failed attempts
• Input Validation - Comprehensive data sanitization and validation

Advanced Network Monitoring

• Multi-Method Device Discovery - ARP, ping, port scan, passive discovery
• Real-Time Traffic Analysis - Deep packet inspection and analysis
• Threat Detection Engine - Port scanning, brute force, DDoS detection
• Anomaly Detection - Machine learning-based behavioral analysis
• Connection Tracking - Real-time network connection monitoring
• Bandwidth Monitoring - Per-device and network-wide traffic analysis

Performance & Security Enhancements

• Advanced Caching System - In-memory caching with TTL support
• Database Optimization - Optimized queries and connection pooling
• Input Sanitization - XSS and injection attack prevention
• Rate Limiting - API endpoint protection
• CSRF Protection - Cross-site request forgery prevention
• Secure Headers - Security-focused HTTP headers

User Interface Improvements

• Responsive Design - Mobile-first responsive layout
• Enhanced Navigation - Role-based menu system
• Real-Time Updates - WebSocket-based live data updates
• Advanced Analytics - Comprehensive network health metrics
• User Management Interface - Complete user administration panel
• Modern UI Components - Glassmorphism effects and animations


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

System Architecture
------------------

Backend Components

Flask Application (app.py)
    Main web server providing session-based authentication, RESTful API endpoints,
    route handling, and template rendering.

Device Scanner (scanner/device_scanner.py)
    Network discovery engine featuring ARP scanning, ping sweep fallback, MAC vendor
    identification, and background daemon thread operation with configurable intervals.

Smart Alert Engine (rules/smart_alert_engine.py)
    Advanced security monitoring system with intelligent rule processing, false positive
    elimination, context-aware evaluation, risk scoring, and alert deduplication.
    Features whitelist-aware processing and learning-based decision making.

Legacy Alert Engine (rules/alert_engine.py)
    Original security monitoring system maintained for backward compatibility.
    Processes events against rule database with basic duplicate prevention.

Database Layer (database/models.py)
    SQLite wrapper providing Kenya timezone support (EAT, UTC+3), dictionary-style
    data access, thread-safe connections, and transaction management.


Frontend Components

Dashboard          : Real-time statistics, network overview, activity timeline, and quick analytics
Analytics Dashboard: Advanced network health metrics, device trends, alert patterns, and vendor distribution
Device Management  : Device listing, search, trust management, and naming with persistence
Alerts Panel       : Alert monitoring, resolution, and false positive marking
Event Logs         : Comprehensive event history with filtering capabilities
Configuration      : System settings and scan interval management
Rules Manager      : Smart rule creation, testing, validation, and management
Language Selector  : Multi-language interface with real-time switching


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Database Schema
---------------

devices - Network devices discovered on the network

    id              : Primary key
    ip_address      : Device IP address
    mac_address     : Device MAC address
    hostname        : Device hostname
    vendor          : MAC vendor name
    first_seen      : First detection timestamp
    last_seen       : Last detection timestamp
    is_trusted      : Trust status (0/1)
    risk_score      : Calculated risk level
    device_name     : User-assigned name


events - System and network events

    id              : Primary key
    timestamp       : Event timestamp (EAT timezone)
    event_type      : Type of event
    device_id       : Associated device ID
    description     : Event description
    metadata        : JSON metadata


alerts - Security alerts and notifications

    id                  : Primary key
    timestamp           : Alert timestamp (EAT timezone)
    rule_id             : Triggering rule ID
    device_id           : Associated device ID
    severity            : Alert severity (low/medium/high)
    message             : Alert message
    is_resolved         : Resolution status (0/1)
    is_false_positive   : False positive flag (0/1)


rules - Alert rule definitions

    id              : Primary key
    name            : Unique rule identifier
    rule_type       : Rule category
    condition       : Evaluation condition
    threshold       : Trigger threshold
    severity        : Alert severity
    enabled         : Active status (0/1)
    description     : Rule description


system_config - Persistent configuration storage

    key             : Configuration key (primary key)
    value           : Configuration value
    updated_at      : Last update timestamp


licenses - License management (FULL license, all features enabled)

system_logs - System operations and error logging


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Security Features
-----------------

Device Discovery & Monitoring

ARP Scanning
    Layer 2 network discovery with MAC address vendor identification
    
Ping Sweep Fallback
    Alternative scanning method for restricted environments
    
Active Device Tracking
    Continuous monitoring of device presence and activity
    
Hostname Resolution
    Automatic device name discovery


Alert System

Built-in Alert Types:

1. New Device Detection
   Alerts when previously unknown devices join the network

2. Frequent Reconnections
   Detects devices with unusual connection patterns

3. Suspicious MAC Addresses
   Identifies potentially spoofed or malicious MAC addresses

4. Device Inactivity
   Monitors devices that go offline unexpectedly

5. IP Address Changes
   Tracks devices changing IP addresses (potential spoofing)

6. Unknown Vendors
   Flags devices with unidentifiable manufacturers


Alert Severity Levels:

LOW    : Informational events requiring awareness
MEDIUM : Suspicious activity requiring investigation
HIGH   : Critical security threats requiring immediate action


Trust Management

Reduce alert fatigue by marking known devices as trusted:

• Trusted devices excluded from new device alerts
• Trust status persists across scans
• Bulk trust operations supported
• Visual trust indicators in device listings


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Smart Alert Engine
------------------

Advanced Rule Processing

The Smart Alert Engine provides enterprise-grade rule processing with intelligent
false positive elimination and context-aware evaluation.

Key Features:

• Whitelist-Aware Processing - Trusted devices excluded from unnecessary alerts
• Alert Deduplication - Hash-based duplicate prevention with cooldown periods
• Risk Scoring - Dynamic severity calculation based on device trust and history
• Learning Data - Historical patterns for smarter decision making
• Rule Testing - Live validation against real devices before deployment
• Smart Validation - Prevents duplicate rule names and validates thresholds
• Performance Optimization - Caching and efficient rule ordering

False Positive Elimination:

• Trusted devices automatically whitelisted from new device alerts
• Smart thresholds prevent normal device behavior from triggering alerts
• Context-aware evaluation considers device history and patterns
• Alert cooldown periods prevent spam from repeated conditions
• Learning-based risk scoring reduces false positives over time

Rule Testing System:

• Test rules against real devices before adding
• Live feedback on whether rules would trigger
• Device context information for informed decisions
• Validation prevents bad rules from being deployed
• Dynamic help text guides appropriate threshold selection

Enhanced Rule Types:

• New Device Detection - Only alerts on truly new devices (1 hour window)
• Reconnect Count - Smart thresholds (20+ for untrusted devices)
• Inactive Duration - 24+ hours offline (not 2 hours)
• MAC Patterns - Enhanced spoofing detection with multiple patterns
• Vendor Unknown - Only for untrusted devices
• IP Changes - Tracks suspicious IP address changes

Performance Features:

• Alert caching prevents duplicate alerts within cooldown periods
• Rule ordering processes high-severity rules first
• Learning data provides historical context for decisions
• Smart cooldowns prevent alert spam
• Efficient database queries with proper indexing


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Custom Rules System
-------------------

Rule Conditions

device_first_seen    : Triggers when device first detected (threshold in days)
reconnect_count      : Exceeds reconnection threshold (count)
inactive_duration    : Device inactive beyond threshold (seconds)
mac_pattern          : Matches suspicious MAC patterns (pattern)
vendor_unknown       : Device has unknown vendor (boolean)
ip_changed           : IP address change detected (boolean)


Rule Properties Example

    name        : high_reconnect_alert
    rule_type   : device_event
    condition   : reconnect_count
    threshold   : 10
    severity    : medium
    enabled     : true
    description : Alert on devices reconnecting more than 10 times


Rule Management

• Add Rules - Create custom rules via /rules page or API
• Edit Rules - Modify thresholds and conditions in real-time
• Toggle Rules - Enable/disable rules without deletion
• Delete Rules - Remove unnecessary rules
• Automatic Reload - Rules apply immediately without restart


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

API Reference
-------------

Authentication

All API endpoints require authenticated session except /login.


Dashboard & Statistics

GET /api/dashboard/stats
    Returns dashboard statistics including total devices, active devices,
    alerts, trusted devices, and new devices today.

GET /api/activity/timeline
    Returns activity data for the last 2 hours, grouped by minute.


Device Management

GET /api/devices
    Lists all discovered devices.

GET /api/devices/active
    Lists only currently active devices.

GET /api/devices/search?q=query
    Searches devices by IP, MAC, hostname, or vendor.
    
    Parameters:
        q (string) - Search query

POST /api/devices/<id>/trust
    Toggles device trust status.

POST /api/devices/<id>/name
    Updates device display name.
    
    Request Body:
        {"name": "Office Printer"}

POST /api/devices/delete
    Deletes multiple devices by ID.
    
    Request Body:
        {"device_ids": [1, 2, 3]}


Alerts & Events

GET /api/alerts?limit=50
    Lists alerts with optional limit parameter.
    
    Parameters:
        limit (integer, optional) - Maximum alerts to return

POST /api/alerts/<id>/resolve
    Marks alert as resolved.

POST /api/alerts/<id>/mark-safe
    Marks alert as false positive.

POST /api/alerts/delete
    Bulk delete alerts.
    
    Request Body:
        {"alert_ids": [1, 2, 3], "delete_resolved": false}

GET /api/events?limit=100
    Lists events with optional limit parameter.

POST /api/events/delete
    Bulk delete events.
    
    Request Body:
        {"event_ids": [1, 2, 3], "delete_all": false}


Network Scanning

GET /api/scan/status
    Returns current scan status and interval.

POST /api/scan/now
    Triggers immediate network scan.

POST /api/scan/start
    Starts background scanning service.

POST /api/scan/stop
    Stops background scanning service.


Configuration

GET /api/config
    Retrieves current system configuration.

POST /api/config/save
    Saves configuration changes (applies immediately).
    
    Request Body:
        {"scan_interval": 120, "scanning_active": true}


Rules Management

GET /api/rules
    Lists all alert rules.

POST /api/rules/add
    Creates new custom rule.
    
    Request Body:
        {
            "name": "unusual_reconnect",
            "rule_type": "device_event",
            "condition": "reconnect_count",
            "threshold": 15,
            "severity": "high",
            "description": "Detects excessive reconnections"
        }

DELETE /api/rules/<id>
    Deletes specific rule.

POST /api/rules/<id>/toggle
    Enables or disables rule.


Utilities

GET /api/timezone/info
    Returns timezone information (Africa/Nairobi, UTC+3).


Analytics & Reporting

GET /api/analytics/device-trends
    Returns device trends, status distribution, and vendor distribution.

GET /api/analytics/alert-trends
    Returns alert trends, types, and hourly distribution patterns.

GET /api/analytics/network-health
    Returns network health metrics with calculated health score and risk levels.


Internationalization

POST /api/language/set
    Sets user language preference in session.
    
    Request Body:
        {"language": "en"}

GET /api/language/current
    Returns current language and available languages.


Rule Testing

POST /api/rules/test
    Tests a rule against a specific device before adding.
    
    Request Body:
        {
            "name": "test_rule",
            "condition": "reconnect_count",
            "threshold": 10,
            "severity": "medium",
            "device_id": 1
        }


Response Format

All API endpoints return JSON with the following structure:

Success Response:
    {"success": true, "data": {...}}

Error Response:
    {"success": false, "error": "Error message"}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configuration System
-------------------

Persistent Configuration

All settings persist to the system_config database table and apply in real-time
without application restart.


Available Settings

scan_interval          : 30-600 seconds (default: 60)
                        Network scan frequency
                        
scanning_active        : boolean (default: true)
                        Enable or disable background scanning
                        
traffic_monitoring     : boolean (default: false)
                        Enable traffic analysis features
                        
extended_logs          : boolean (default: true)
                        Enable detailed logging
                        
email_alerts           : boolean (default: false)
                        Enable email notifications
                        
alert_retention_days   : 1-365 days (default: 90)
                        Days to retain alerts before cleanup
                        
log_retention_days     : 1-365 days (default: 365)
                        Days to retain logs before cleanup


Configuration Behavior

• Settings saved via /api/config/save take effect immediately
• Scanner loop polls database before each scan cycle
• No application restart required for configuration changes
• Thread-safe configuration access across all components


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Network Scanning Capabilities
-----------------------------

Scanning Methods

ARP Scanning (Primary)
    • Layer 2 network discovery
    • Requires elevated privileges (root/administrator)
    • Most accurate method for local network
    • Provides MAC address information
    • Vendor identification via MAC OUI lookup

Ping Sweep (Fallback)
    • ICMP-based device discovery
    • Used when ARP scanning unavailable
    • Works in containerized environments
    • Limited to IP address detection


Limitations

Privilege Requirements
    ARP scanning requires raw socket access
    
Container Restrictions
    May not work in Docker/Replit due to network isolation
    
Network Scope
    Limited to local subnet
    
Firewall Impact
    Some devices may not respond to scans


Network Interface Detection

The system automatically:
    • Identifies active network interfaces
    • Selects best interface for scanning
    • Falls back to alternative methods if primary fails
    • Logs interface selection for troubleshooting


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Security Considerations
-----------------------

Production Deployment Checklist

1. Change Default Credentials
   Always set ADMIN_USERNAME and ADMIN_PASSWORD environment variables

2. Secure Session Key
   Configure unique SESSION_SECRET value

3. Enable HTTPS
   Deploy behind reverse proxy with SSL/TLS

4. Configure Firewall
   Restrict access to port 5000 to trusted networks only

5. Privilege Management
   Run with minimal required privileges


Authentication & Authorization

• Session-based authentication protects all routes except /login
• Sessions expire after inactivity period
• Input validation on all API endpoints prevents injection attacks
• All operations logged for audit trail


Database Security

• SQLite suitable for deployments up to 1000 devices
• Thread-safe connections prevent race conditions
• Regular backups recommended for production environments
• Consider PostgreSQL for larger deployments (1000+ devices)


Network Security

• Scanning features require appropriate system permissions
• All operations logged for audit trail
• Trust management reduces false positive alert fatigue
• Rule-based alerting configurable to match security policy


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File Structure
--------------

netwatch-siem/
│
├── app.py                          Main Flask application
├── config.py                       Configuration management
├── netwatch.db                     SQLite database
├── requirements.txt                Python dependencies
│
├── database/
│   └── models.py                   Database wrapper and models
│
├── scanner/
│   ├── device_scanner.py           Network scanning engine
│   └── enhanced_scanner.py         Enhanced scanner with persistence
│
├── rules/
│   ├── alert_engine.py             Legacy alert processing engine
│   └── smart_alert_engine.py       Smart alert engine with false positive elimination
│
├── i18n/
│   ├── __init__.py                 Internationalization manager
│   └── translations/
│       ├── en.json                 English translations
│       ├── es.json                 Spanish translations
│       ├── fr.json                 French translations
│       ├── de.json                 German translations
│       └── zh.json                 Chinese translations
│
├── templates/
│   ├── base.html                   Base template with i18n support
│   ├── login.html                  Login page
│   ├── dashboard.html              Dashboard view with quick analytics
│   ├── analytics.html              Advanced analytics dashboard
│   ├── devices.html                Device management
│   ├── alerts.html                 Alerts panel
│   ├── logs.html                   Event logs
│   ├── config.html                 System configuration
│   └── rules.html                  Smart rules management with testing
│
└── static/
    ├── css/
    │   ├── main.css                Main stylesheet
    │   └── cyber-theme.css         Dark cyber theme with animations
    │
    └── js/
        ├── dashboard.js            Dashboard logic with analytics
        ├── analytics.js            Analytics dashboard functionality
        ├── devices.js              Device management
        └── alerts.js               Alerts handling


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Troubleshooting
---------------

ARP Scanning Not Working

Symptoms: No devices discovered, empty device list

Solutions:
    1. Ensure application runs with elevated privileges
       sudo python app.py
       
    2. Check network interface is active and connected
    
    3. Verify firewall allows outbound ARP packets
    
    4. Review system logs for scanning errors
    
    5. Test ping sweep fallback method


Configuration Changes Not Applying

Symptoms: Settings revert after changing, scan interval unchanged

Solutions:
    1. Verify database write permissions
    
    2. Check for error messages in system logs
    
    3. Ensure configuration API endpoints returning success
    
    4. Restart application if database locked
    
    5. Confirm no conflicting environment variables


High Alert Volume

Symptoms: Too many alerts, alert fatigue

Solutions:
    1. Mark known devices as trusted
    
    2. Adjust rule thresholds in Rules Manager
    
    3. Disable overly sensitive rules
    
    4. Review and resolve false positive alerts
    
    5. Configure appropriate retention periods


Database Connection Errors

Symptoms: Application crashes, database locked errors

Solutions:
    1. Ensure only one instance running
    
    2. Check database file permissions
    
    3. Verify sufficient disk space
    
    4. Review connection pool settings
    
    5. Consider database backup and restore


System Logs

Access system logs via:
    • Web interface: /logs page
    • Database: system_logs table
    • API: /api/events endpoint


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Development Notes
-----------------

Development Environment

• Server binds to 0.0.0.0:5000 for broad compatibility
• Background scanner runs in daemon thread for automatic cleanup
• Flask debug mode disabled for production-like behavior
• PYTHONPATH configured for module imports
• Database file tracked in git for easier setup


Feature Flags

All features currently enabled by default (FULL license mode):
    • Device scanning and monitoring
    • Custom alert rules
    • Trust management
    • Bulk operations
    • Configuration persistence
    • Event logging


Timezone Handling

All timestamps use Kenya timezone (EAT, UTC+3):
    • Database stores ISO 8601 formatted timestamps
    • Frontend displays in local timezone
    • API returns timezone information via /api/timezone/info


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Future Enhancements
-------------------

Planned Features

Email Notifications
    Critical alert delivery via email with customizable templates

Traffic Monitoring
    Deep packet inspection and network traffic analysis

Network Topology
    Visual network mapping and relationship visualization

Threat Intelligence
    Integration with external threat feeds and indicators of compromise

Report Export
    PDF and CSV export functionality for compliance and reporting

Multi-User Support
    Role-based access control (RBAC) with user management

API Authentication
    Token-based authentication for external system integrations

Performance Optimization
    Enhanced support for large networks (1000+ devices)

Real-time Updates
    WebSocket-based live dashboard updates without page refresh

Mobile Application
    Native mobile app for on-the-go network monitoring


Contribution Guidelines

Contributions welcome! Please follow these steps:

1. Fork the repository
2. Create feature branch
3. Commit with clear messages
4. Submit pull request with description
5. Ensure tests pass and documentation updated


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dependencies
------------

Python Libraries

Flask       : Web framework and routing engine
Scapy       : Network packet manipulation and ARP scanning
psutil      : System and network interface information
sqlite3     : Database operations (Python standard library)


Frontend Libraries

Tailwind CSS    : Utility-first styling framework
Feather Icons   : Icon system for UI elements
Chart.js        : Data visualizations and activity timeline
JavaScript      : Vanilla JavaScript, no heavy frameworks


Infrastructure Requirements

• Local network access for device scanning
• Elevated privileges for ARP scanning (optional but recommended)
• Email server for alert notifications (optional)
• Offline operation fully supported with local data storage


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

License
-------

NetWatch SIEM is currently configured with FULL license, enabling all features
without restrictions.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Support
-------

For issues, questions, or contributions:

• Review this documentation thoroughly
• Check troubleshooting section for common issues
• Examine system logs for error details
• Submit issues with detailed reproduction steps


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Changelog
---------

Version 2.1 (October 18, 2025) - BUG FIX RELEASE

Critical Bug Fixes
    ✓ Fixed 'IPv4Network' object has no attribute 'num_hosts' error
    ✓ Corrected ipaddress module usage in advanced_scanner.py
    ✓ Network configuration now properly calculates host counts
    ✓ Eliminated repeated "Error getting network info" messages
    ✓ Improved network discovery reliability and stability

Version 2.0 (October 18, 2025) - MAJOR ENHANCEMENT RELEASE

Smart Alert Engine
    ✓ Advanced rule processing with false positive elimination
    ✓ Context-aware evaluation with risk scoring
    ✓ Alert deduplication with hash-based prevention
    ✓ Whitelist-aware processing for trusted devices
    ✓ Learning-based decision making with historical patterns
    ✓ Rule testing system with live device validation
    ✓ Smart validation preventing duplicate rules and bad thresholds
    ✓ Performance optimization with caching and efficient ordering

Analytics Dashboard
    ✓ Real-time network health metrics with calculated scores
    ✓ Device trends and status distribution analysis
    ✓ Alert patterns and hourly distribution charts
    ✓ Vendor distribution and top device analysis
    ✓ Risk level categorization and assessment
    ✓ Interactive charts with Chart.js integration
    ✓ Quick analytics cards on main dashboard

Internationalization
    ✓ Multi-language support (English, Spanish, French, German, Chinese)
    ✓ Real-time language switching without page reload
    ✓ Session-based language persistence
    ✓ Complete UI translation coverage
    ✓ Dynamic language selector in header

Device Persistence
    ✓ Enhanced device name and trust status persistence
    ✓ Multiple lookup strategies for device identification
    ✓ Smart updates preserving user customizations
    ✓ MAC-first and IP fallback detection methods
    ✓ No more lost device names when devices go offline/online

Enhanced Rules System
    ✓ Live rule testing against real devices
    ✓ Dynamic threshold guidance with context-aware help
    ✓ Smart validation preventing bad rule creation
    ✓ Enhanced rule types with improved thresholds
    ✓ Test button for rule validation before deployment
    ✓ Real-time feedback on rule behavior

User Interface Improvements
    ✓ Analytics dashboard with comprehensive metrics
    ✓ Quick analytics cards on main dashboard
    ✓ Enhanced rules page with testing capabilities
    ✓ Language selector with real-time switching
    ✓ Improved device management with persistence
    ✓ Better visual feedback and user guidance

API Enhancements
    ✓ Analytics endpoints for comprehensive reporting
    ✓ Rule testing API for live validation
    ✓ Language management endpoints
    ✓ Enhanced device persistence endpoints
    ✓ Improved error handling and validation

Performance Optimizations
    ✓ Smart alert caching preventing duplicate processing
    ✓ Efficient rule ordering and processing
    ✓ Learning data integration for smarter decisions
    ✓ Optimized database queries with proper indexing
    ✓ Background processing improvements

Version 1.0 (October 17, 2025)

Core Features
    ✓ Initial release with complete SIEM functionality
    ✓ Real-time network device discovery
    ✓ Rule-based security alerting
    ✓ Comprehensive event logging
    ✓ Trust management system

Configuration System
    ✓ Database-backed persistent configuration
    ✓ Real-time configuration application
    ✓ Dynamic scanner control
    ✓ Environment-based credentials

Alert Engine
    ✓ Dynamic rule evaluation from database
    ✓ Configurable conditions and thresholds
    ✓ Severity classification
    ✓ Duplicate prevention

User Interface
    ✓ Dark cyber theme with glassmorphism effects
    ✓ Responsive mobile-friendly design
    ✓ Separated CSS and JavaScript modules
    ✓ Color-coded status indicators

API Enhancements
    ✓ Complete RESTful API
    ✓ Bulk operations support
    ✓ Enhanced trust management
    ✓ Configuration endpoints

Bug Fixes
    ✓ Resolved database connection issues
    ✓ Fixed scanner control edge cases
    ✓ Corrected timezone handling
    ✓ Improved error handling


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Documentation Version: 2.0
Last Updated: October 18, 2025
NetWatch SIEM - Advanced Network Security Monitoring System

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━



