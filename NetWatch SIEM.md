# NetWatch SIEM - Network Monitoring System

## Overview

NetWatch SIEM is a Flask-based network security monitoring system that continuously scans local networks to detect, track, and alert on device activity and potential security threats. The system provides real-time device discovery, event logging, rule-based alerting, and a comprehensive dashboard for network visibility. Built for simplicity and offline operation, it uses SQLite for data persistence and provides both LITE and PRO licensing tiers.

## Recent Changes

**October 11, 2025**:
- Complete system rebuild with modular frontend architecture
- Fixed critical database connection bug in alert engine (check_frequent_reconnect method)
- Implemented professional cyber-themed UI with dark mode and glassmorphism effects
- Created modular template structure (base.html extends pattern)
- Separated CSS into main.css and cyber-theme.css files
- Built standalone JavaScript modules for dashboard, devices, and alerts with AJAX updates
- All Flask routes and API endpoints working correctly
- System verified and tested by architect
- Added session-based authentication (username: Mark, password: lizzyjohn)
- Removed all PRO license restrictions - all features are fully unlocked for everyone
- Implemented responsive design with hamburger menu for mobile screens
- All user data (devices, alerts, events, rules) is dynamic from SQLite database
- Application configuration (license type, feature flags) managed via config.py

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture

**Framework**: Flask (Python 3.x) web application with modular component design

**Core Components**:
- **Device Scanner** (`scanner/device_scanner.py`): Uses Scapy for ARP scanning and network device discovery. Maintains MAC vendor database for device identification. Runs as background thread with configurable scan intervals.
- **Alert Engine** (`rules/alert_engine.py`): Rule-based alerting system that processes device events and triggers alerts based on predefined conditions (new devices, frequent reconnections, suspicious activity).
- **Database Layer** (`database/models.py`): SQLite database wrapper managing devices, events, alerts, rules, licenses, and system logs. Uses row factory for dictionary-style access.

**Design Pattern**: The application follows a service-oriented pattern where independent modules (scanner, alerts, database) communicate through the shared database layer. Background scanning runs in a separate thread to avoid blocking the web interface.

**Configuration Management**: Two-tier configuration system (Config and ProConfig classes) in `config.py` enables feature gating between LITE and PRO versions. Settings include scan intervals, alert thresholds, retention policies, and feature flags.

**Rationale**: Modular architecture allows independent development and testing of scanning, alerting, and data persistence. Thread-based background scanning enables continuous monitoring without impacting UI responsiveness.

### Frontend Architecture

**Technology Stack**: Vanilla JavaScript, HTML5, Tailwind CSS (CDN), Feather Icons

**UI Components**:
- Dashboard with real-time statistics and network activity visualization
- Device list with trust management and status tracking
- Alert management panel with severity-based filtering
- Event logs viewer with filtering capabilities
- Configuration panel for scan settings and alert preferences

**Data Flow**: Frontend uses fetch API for asynchronous JSON communication with Flask backend. Auto-refresh mechanisms update data every few seconds without page reloads. Pages extend a base template for consistent navigation and styling.

**Design Choice**: Pure vanilla JavaScript chosen over frameworks to minimize dependencies and maintain simplicity. Tailwind CSS provides rapid styling through utility classes without custom CSS overhead.

**Theme**: Dark "cyber" theme with glassmorphism effects, color-coded status indicators, and monospace fonts for technical aesthetics.

### Data Layer

**Database**: SQLite (`netwatch.db`) with the following schema:

- **devices**: Stores IP, MAC, hostname, vendor, trust status, risk score, timestamps, reconnect counts
- **events**: Logs all network events with timestamps, severity, type, and device associations
- **alerts**: Manages triggered alerts with status tracking (active/resolved)
- **rules**: Configurable alert rules with enable/disable flags
- **licenses**: License key validation and feature unlocking
- **system_logs**: Application-level logging

**Design Decision**: SQLite chosen for zero-configuration deployment, offline operation, and simplicity. No external database server required. Row factory pattern enables clean dictionary-based data access.

**Data Retention**: Configurable retention periods (30 days for alerts, 90 days for logs) to manage database growth.

### Security & Monitoring Features

**Device Discovery**: ARP scanning with vendor identification using MAC prefix lookup table. Tracks device lifecycle (first_seen, last_seen, status changes).

**Alert Rules**:
- New device detection (immediate alert for unknown devices)
- Reconnection frequency monitoring (threshold-based alerts)
- Suspicious MAC prefix detection (configurable blacklist)
- Inactivity timeout tracking
- Traffic spike detection (PRO feature)

**Trust Management**: Devices can be marked as trusted to reduce noise from known-good devices while maintaining audit logs.

**Licensing System**: Two-tier model (LITE/PRO) with feature flags. PRO unlocks faster scanning, traffic monitoring, extended logs, and email alerts.

### API Design

**RESTful Endpoints**:
- `/api/devices` - Device listing and management
- `/api/alerts` - Alert retrieval and resolution
- `/api/events` - Event log access
- `/api/dashboard/stats` - Real-time statistics
- `/api/devices/{id}/trust` - Trust status updates

**Response Format**: Consistent JSON structure with `success` boolean and `data` payload. Error responses include descriptive messages.

## External Dependencies

### Python Libraries
- **Flask**: Web framework for routing, templating, and request handling
- **Scapy**: Network packet manipulation for ARP scanning and device discovery
- **psutil**: System and network statistics (used for traffic monitoring in PRO version)
- **sqlite3**: Built-in database interface (no external dependency)

### Frontend Libraries (CDN)
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **Feather Icons**: Icon set for UI elements
- **Chart.js** (implied): Network activity visualization (referenced in templates)

### Network Requirements
- Local network access for ARP scanning
- Raw socket access may require elevated privileges for Scapy operations

### Optional Integrations
- **Email alerts** (PRO feature): SMTP configuration for alert notifications (implementation pending)
- **MAC vendor database**: Embedded vendor lookup table, could be extended with external OUI database

### Infrastructure
- **No external APIs**: System operates entirely offline
- **No cloud services**: All data stored locally in SQLite
- **No authentication provider**: Simple session-based access (SECRET_KEY configuration)