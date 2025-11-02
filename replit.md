# NetWatch SIEM - Replit Configuration

## Project Overview
Enterprise-grade Security Information and Event Management (SIEM) system for network surveillance and threat detection. Created by John O. Mark.

## Current State
- **Status**: ✅ Fixed critical bugs and optimized for both cloud and on-premises deployment
- **Scanner**: Working with graceful fallback from privileged to unprivileged scanning methods
- **Frontend**: Fully responsive, deployed on port 5000

## Technology Stack
- **Backend**: Flask + Flask-SocketIO (Python 3.11)
- **Database**: SQLite (netwatch.db)
- **Frontend**: HTML5, Vanilla JS, Tailwind CSS
- **Network Tools**: Scapy, Nmap, psutil

## Critical Bugs Fixed
1. **ARP Scanning** (`monitoring/advanced_scanner.py`)
   - FIXED: Changed `sr()` to `srp()` with Ethernet broadcast frame
   - Root cause: ARP is layer-2 protocol, requires Ethernet header
   - Impact: Now properly discovers devices on local network

2. **Ping Sweep Timeout** (`monitoring/advanced_scanner.py`)
   - FIXED: Removed `timeout=1` from `future.result()`
   - Root cause: 1-second timeout dropped all ping responses that took ~1s
   - Impact: Now receives all ping responses correctly

3. **Trust Status Checkbox** (`security/schemas.py`)
   - FIXED: Changed schema from `type: 'bool'` to `type: 'int'`
   - Root cause: JavaScript sends 0/1 (int) but schema expected boolean
   - Impact: Trust status toggle now works without errors

4. **MAC Address Missing** (`monitoring/advanced_scanner.py`)
   - FIXED: Generate pseudo-MAC addresses from IP when ARP unavailable
   - Root cause: Ping sweep couldn't get MAC without ARP, app crashed on missing key
   - Impact: Scanner works in both privileged and unprivileged environments

## Recent Changes (November 2, 2025)
- Fixed layer-2 ARP scanning implementation
- Removed ping response timeout bug
- Added MAC address generation for non-ARP environments
- Fixed trust status validation schema
- Configured deployment for production (VM mode)

## Deployment
- **Dev Server**: Port 5000 (0.0.0.0)
- **Production**: Configured for VM deployment with `python app.py`
- **Auth**: Default credentials Mark/lizzyjohn (change in production)
