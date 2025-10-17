NetWatch SIEM - Network Monitoring System

Overview

NetWatch SIEM is a Flask-based network security monitoring system. It continuously scans local networks to detect devices, track activity, and alert on potential security threats. Features include real-time device discovery, event logging, rule-based alerts, and a dashboard for network visibility. The system is lightweight, works offline, and uses SQLite for data storage. Both LITE and PRO versions are supported.

Recent Changes (October 11, 2025)

- Rebuilt system with modular frontend structure
- Fixed critical database connection bug in alert engine
- Updated UI with dark theme and glassmorphism effects
- Created modular templates (base.html pattern)
- Separated CSS into main.css and cyber-theme.css
- Built standalone JavaScript modules for dashboard, devices, and alerts
- All Flask routes and APIs fully functional
- Added session-based login (username: Mark, password: lizzyjohn)
- Removed PRO restrictions; all features now unlocked
- Implemented responsive design with mobile-friendly menu
- All data (devices, alerts, events, rules) dynamically loaded from SQLite
- Configuration managed via config.py

System Architecture

Backend

- Framework: Flask (Python 3.x)
- Device Scanner: Uses Scapy for ARP scanning and MAC vendor identification. Runs in background thread.
- Alert Engine: Processes events and triggers alerts based on rules (new devices, frequent reconnections, suspicious activity).
- Database Layer: SQLite wrapper managing devices, events, alerts, rules, licenses, and logs. Supports dictionary-style access.
- Design: Service-oriented; modules communicate via database. Background scanning runs in a separate thread.
- Configuration: Managed in config.py with LITE/PRO feature gating. Settings include scan intervals, alert thresholds, and retention policies.

Frontend

- Stack: HTML5, Vanilla JavaScript, Tailwind CSS, Feather Icons
- Components: Dashboard, device list, alert panel, event log viewer, configuration panel
- Data Flow: Frontend fetches JSON from backend; auto-refresh updates data without reloading.
- Design: Vanilla JavaScript avoids extra dependencies; Tailwind provides fast styling.
- Theme: Dark "cyber" theme with glassmorphism effects and color-coded status indicators.

Data Layer

- Database: SQLite (netwatch.db)
- Tables: devices, events, alerts, rules, licenses, system_logs
- Retention: Alerts 30 days, logs 90 days
- Reasoning: SQLite allows offline, zero-configuration deployment.

Security & Monitoring

- Device Discovery: ARP scanning with vendor identification
- Alerts: New devices, frequent reconnections, suspicious MACs, inactivity, traffic spikes (PRO)
- Trust Management: Mark devices as trusted to reduce noise
- Licensing: LITE/PRO model with feature flags. PRO enables faster scans, traffic monitoring, extended logs, and email alerts.

API

- Endpoints:
  - /api/devices – list and manage devices
  - /api/alerts – retrieve and resolve alerts
  - /api/events – access event logs
  - /api/dashboard/stats – real-time stats
  - /api/devices/{id}/trust – update trust status
- Format: JSON responses with success boolean and data payload; errors include messages.

Dependencies

- Python: Flask, Scapy, psutil (PRO), sqlite3
- Frontend: Tailwind CSS, Feather Icons, Chart.js (visualizations)
- Network: Local network access required; elevated privileges may be needed for Scapy
- Optional: Email alerts (PRO), external MAC vendor database
- Infrastructure: Offline operation, all data local, simple session authentication




