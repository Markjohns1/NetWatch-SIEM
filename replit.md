# NetWatch SIEM - Replit Setup

## Overview
NetWatch SIEM is an enterprise-grade Security Information and Event Management System built with Flask. This project provides network monitoring, alert management, and security event tracking capabilities through a modern web interface.

## Project Information
- **Type**: Flask Web Application (SIEM Platform)
- **Language**: Python 3.11+
- **Framework**: Flask 3.1.2 with Flask-SocketIO for real-time features
- **Database**: SQLite 3 (netwatch.db)
- **Frontend**: HTML5, JavaScript, Tailwind CSS
- **Real-time Communication**: Socket.IO (WebSockets)

## Current State
The application is fully configured and running in the Replit environment:
- ✅ All Python dependencies installed
- ✅ Workflow configured on port 5000
- ✅ Database initialized with default admin user
- ✅ Deployment configuration set to autoscale
- ✅ Application accessible via webview

## Default Login Credentials
**IMPORTANT**: Use these credentials for first login, then change the password immediately!
- **Username**: `admin` (can be overridden with `DEFAULT_ADMIN_USERNAME` env var)
- **Password**: `admin123` (can be overridden with `DEFAULT_ADMIN_PASSWORD` env var)

You can customize these at startup using environment variables:
```bash
DEFAULT_ADMIN_USERNAME=myuser
DEFAULT_ADMIN_PASSWORD=mypassword
DEFAULT_ADMIN_EMAIL=admin@mydomain.com
```

## Key Features
- Multi-User Authentication with PBKDF2 hashing
- Role-based access control (Admin, Operator, Analyst, Viewer)
- Smart Alert Engine with context-aware processing
- Custom Security Rules System
- Real-Time Dashboard with WebSocket updates
- Multi-Language Support (English, Spanish, French, German, Chinese)
- Advanced Analytics and reporting
- RESTful API for programmatic access

## Architecture

### Project Structure
```
netwatch-siem/
├── app.py                  # Main Flask application
├── config.py              # Configuration settings
├── database/              # Database models and operations
│   ├── models.py         # SQLite database management
├── models/               # User management
│   └── user.py          # User model and authentication
├── security/            # Security features
│   ├── auth.py         # Authentication middleware
│   ├── rbac.py         # Role-based access control
│   └── schemas.py      # Input validation schemas
├── scanner/            # Network scanning modules
│   ├── device_scanner.py
│   ├── enhanced_scanner.py
│   ├── hostname_resolver.py
│   └── network_scanner.py
├── monitoring/         # Advanced monitoring
│   ├── advanced_scanner.py
│   └── traffic_analyzer.py
├── rules/             # Alert rules engine
│   ├── alert_engine.py
│   ├── smart_alert_engine.py
│   └── condition_metadata.py
├── i18n/             # Internationalization
│   └── translations/ # Language files
├── static/          # CSS and JavaScript
├── templates/       # HTML templates
└── utils/          # Utility functions
```

### Database Schema
The SQLite database includes:
- **devices** - Network device inventory
- **alerts** - Security alerts and notifications
- **rules** - Custom alert rule definitions
- **users** - User accounts and authentication
- **events** - System and network event log
- **system_config** - Persistent configuration

## Replit Configuration

### Workflow
- **Name**: NetWatch SIEM
- **Command**: `python app.py`
- **Port**: 5000 (exposed via webview)
- **Host**: 0.0.0.0 (configured for Replit proxy)

### Deployment
- **Type**: Autoscale (stateless web application)
- **Command**: `python app.py`

### Environment Variables
The application uses the following environment variables:
- `SESSION_SECRET` - Flask session secret key (auto-generated if not set)
- `ADMIN_USERNAME` - Override default admin username (optional)
- `ADMIN_PASSWORD` - Override default admin password (optional)

## Dependencies
All dependencies are managed via `pyproject.toml`:
- flask (3.1.2) - Web framework
- flask-socketio (5.5.1) - WebSocket support
- werkzeug (3.1.3) - WSGI utilities
- scapy (2.6.1) - Network packet manipulation
- python-nmap (0.7.1) - Network scanning
- psutil (7.1.0) - System monitoring
- dnspython (2.8.0) - DNS utilities
- requests (2.32.5) - HTTP client

## Limitations in Replit Environment

### Network Scanning
Network scanning features (ARP scanning, port scanning, packet capture) require root/administrator privileges and are **limited in containerized environments** like Replit. The application handles this gracefully:
- Network scanner will show limited results
- All other features (web interface, user management, alerts, analytics) work fully
- The application automatically continues without network scanning privileges

### What Works Fully
- ✅ Web interface and dashboard
- ✅ User authentication and management
- ✅ Alert management (manual and rule-based)
- ✅ Custom rule creation and testing
- ✅ Analytics and reporting
- ✅ Real-time WebSocket updates
- ✅ Multi-language support
- ✅ RESTful API

## API Endpoints
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET/POST /api/devices` - Device management
- `GET/POST /api/alerts` - Alert management
- `GET/POST /api/rules` - Custom rule management
- `GET /api/analytics/*` - Analytics data
- `GET/POST /api/users` - User management (admin only)

## Recent Changes (Import Setup - Nov 7, 2025)
- Installed all Python dependencies via packager
- Configured workflow for port 5000 with webview
- Set up deployment configuration for autoscale
- Database auto-initialized with default admin user
- Application verified running and accessible

## Security Notes
- Change default admin password immediately after first login
- All passwords are hashed using PBKDF2
- CSRF protection enabled
- Session management with secure cookies
- Role-based access control enforced on all routes

## Development Notes
- The application uses SQLite in WAL mode for better concurrency
- WebSocket connections use threading mode for real-time updates
- Database initialization happens automatically on first run
- Translations are loaded from i18n/translations/ directory

## For Production Use
If deploying to production outside Replit:
1. Use a production WSGI server (gunicorn recommended)
2. Set a strong SESSION_SECRET environment variable
3. Consider using PostgreSQL instead of SQLite for better scalability
4. Install Tailwind CSS properly (currently using CDN)
5. Run with elevated privileges if network scanning is needed

## Support
For issues or questions about the NetWatch SIEM platform, refer to the main README.md and NetWatch SIEM.md documentation files.
