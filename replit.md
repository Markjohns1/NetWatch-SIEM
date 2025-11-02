# NetWatch SIEM - Replit Configuration

## Project Overview
Enterprise-grade Security Information and Event Management (SIEM) system for network surveillance and threat detection. Created by John O. Mark.

## Current State
- **Status**: Setting up for Replit cloud environment
- **Challenge**: Original code designed for physical network scanning (ARP, raw sockets) which requires root privileges
- **Solution in Progress**: Adapting to work with ping-based discovery and simulated network data for cloud demo

## Architecture Issues Being Fixed
1. **Network Discovery Limitation**: Replit runs in isolated container with no physical network access
   - ARP scanning requires raw socket access (root privileges) ❌
   - Port scanning requires root privileges ❌
   - Ping sweep works but can't get MAC addresses without ARP ✓
   
2. **Critical Bug**: Scanner crashes with KeyError: 'mac' when ping sweep returns devices without MAC addresses
   - Location: `app.py` line 141 expects `device_dict['mac']`
   - Ping sweep returns IP only, no MAC address
   - Need to generate pseudo-MAC addresses for cloud environment

## Technology Stack
- **Backend**: Flask + Flask-SocketIO (Python 3.11)
- **Database**: SQLite (netwatch.db)
- **Frontend**: HTML5, Vanilla JS, Tailwind CSS
- **Network Tools**: Scapy, Nmap, psutil (limited functionality without root)

## Current Focus
Backend functionality - making network discovery work in containerized/cloud environment where physical network scanning isn't possible.

## Next Steps
1. Fix ping sweep to generate MAC addresses from IP addresses
2. Make all scanner methods return consistent device format
3. Add demo/mock network mode for cloud environments
4. Ensure graceful degradation when privileged operations fail
