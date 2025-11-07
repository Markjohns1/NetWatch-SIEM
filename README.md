# NetWatch SIEM

**Enterprise-grade Security Information and Event Management System**

A Flask-based SIEM platform for network monitoring, alert management, and security event tracking. Built with Python, Flask, and SQLite.

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netwatch-siem.git
cd netwatch-siem

# Install dependencies
pip install -r netwatch-siem-requirements.txt

# Run the application
python app.py
```

Access the dashboard at: **http://localhost:5000**

### Default Login
- **Username:** `admin`
- **Password:** `admin123`

⚠️ **IMPORTANT: Change the password immediately after first login!**

## ✨ Features

- **Multi-User Authentication** - PBKDF2 hashing, role-based access control
- **Smart Alert Engine** - Context-aware alert processing with deduplication
- **Custom Rules System** - Create and test custom security alert rules
- **Real-Time Dashboard** - WebSocket-based live updates
- **Multi-Language Support** - English, Spanish, French, German, Chinese
- **Advanced Analytics** - Device trends, alert patterns, network health
- **RESTful API** - Complete programmatic access
- **User Management** - Full admin panel for user/role management

## 📋 Requirements

- Python 3.11+
- SQLite 3
- Root/Administrator privileges (for network scanning features)

## 🛠️ Technology Stack

- **Backend:** Flask 3.1.2, Flask-SocketIO 5.5.1
- **Frontend:** HTML5, JavaScript, Tailwind CSS
- **Database:** SQLite 3
- **Real-time:** Socket.IO (WebSockets)
- **Security:** PBKDF2, CSRF protection, session management

## 📖 Documentation

See [NetWatch SIEM.md](NetWatch%20SIEM.md) for complete documentation including:
- API reference
- Database schema
- Configuration options
- Deployment guide
- Security features

## 🔐 User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full system access, user management |
| **Operator** | Device & alert management, rule creation |
| **Analyst** | View-only access to alerts and analytics |
| **Viewer** | Dashboard viewing only |

## 🌐 API Endpoints

- `/api/dashboard/stats` - Dashboard statistics
- `/api/devices` - Device management
- `/api/alerts` - Alert management
- `/api/rules` - Custom rule management
- `/api/analytics/*` - Analytics data
- `/api/users` - User management (admin only)

Full API documentation in [NetWatch SIEM.md](NetWatch%20SIEM.md)

## ⚙️ Configuration

Configure via environment variables:

```bash
export SESSION_SECRET="your_secret_key"
```

The default admin user (`admin / admin123`) is created automatically on first run. You can customize the admin credentials using environment variables:

```bash
export DEFAULT_ADMIN_USERNAME="yourusername"
export DEFAULT_ADMIN_PASSWORD="yourpassword"
export DEFAULT_ADMIN_EMAIL="admin@yourdomain.com"
```

**Important:** Change the default password immediately after logging in!

Use the web-based configuration panel at `/config` for system settings.

## 🐳 Deployment

### Production Setup

```bash
# Use a production WSGI server
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker/Replit Limitations

Network scanning features require root privileges and are unavailable in containerized environments. The web interface, user management, and all CRUD operations work fully.

## 📊 Database Schema

- **devices** - Network device inventory
- **alerts** - Security alerts and notifications
- **rules** - Custom alert rule definitions
- **users** - User accounts and authentication
- **events** - System and network event log
- **system_config** - Persistent configuration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

**John O. Mark**

## 🙏 Acknowledgments

- Built with Flask and Flask-SocketIO
- UI powered by Tailwind CSS
- Network scanning via Scapy and python-nmap

---

**Note:** Network scanning features (ARP, port scanning, packet capture) require elevated privileges and may not work in containerized environments like Docker or Replit. All other features (web interface, alerts, user management, analytics) work without restrictions.
