#!/usr/bin/env python3
"""Test improved scanning performance"""

from scanner.device_scanner import DeviceScanner
from database.models import Database

def main():
    db = Database()
    scanner = DeviceScanner(db, verbose=True, show_banner=False)

    print('Testing improved scanning performance...')
    print('This should find more devices including phones...')
    
    devices = scanner.smart_scan()
    print(f'Found {len(devices)} devices:')
    
    for i, device in enumerate(devices):
        print(f'Device {i+1}:')
        print(f'  IP: {device.get("ip", "Unknown")}')
        print(f'  Hostname: {device.get("hostname", "Unknown")}')
        print(f'  Device Type: {device.get("device_type", "Unknown")}')
        print(f'  Vendor: {device.get("vendor", "Unknown")}')
        print(f'  MAC: {device.get("mac", "Unknown")}')
        print(f'  Discovery Method: {device.get("discovery_method", "Unknown")}')
        print()

if __name__ == "__main__":
    main()

