# Enhanced Device Scanner with Improved Persistence and Performance
import socket
import subprocess
import re
from scapy.all import ARP, Ether, srp
import psutil
from datetime import datetime, timedelta
import threading
import time
import ipaddress
import logging
import hashlib
import os
import concurrent.futures
from collections import defaultdict
import json

class EnhancedDeviceScanner:
    def __init__(self, db, verbose=False, show_banner=True):
        self.db = db
        self.verbose = verbose
        self.show_banner = show_banner
        self.device_cache = {}  # Cache for device lookups
        self.performance_stats = {
            'scans_completed': 0,
            'devices_found': 0,
            'avg_scan_time': 0,
            'last_scan_duration': 0
        }
        
        # Enhanced MAC vendor database
        self.mac_vendors = self._load_enhanced_mac_vendors()
        
        # Performance optimization settings
        self.cache_ttl = 300  # 5 minutes
        self.parallel_workers = 4
        self.scan_timeout = 2
        
    def _load_enhanced_mac_vendors(self):
        """Load enhanced MAC vendor database"""
        return {
            # Virtualization
            '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
            '00:1C:14': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen', 'DC:A6:32': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi', '00:1A:7D': 'Kindle', '00:17:88': 'Philips',
            
            # Major manufacturers
            '00:1B:63': 'Apple', '00:1E:52': 'Apple', '00:23:DF': 'Apple',
            '00:25:00': 'Apple', '00:25:4B': 'Apple', '00:26:08': 'Apple',
            '00:26:4A': 'Apple', '00:26:B0': 'Apple', '00:26:BB': 'Apple',
            '00:50:C2': 'Apple', '04:0C:CE': 'Apple', '04:0E:3C': 'Apple',
            '04:15:52': 'Apple', '04:1E:64': 'Apple', '04:26:65': 'Apple',
            '04:32:F4': 'Apple', '04:4B:ED': 'Apple', '04:52:C7': 'Apple',
            '04:54:53': 'Apple', '04:69:F8': 'Apple', '04:7C:16': 'Apple',
            '04:8D:38': 'Apple', '04:9F:CA': 'Apple', '04:A3:16': 'Apple',
            '04:DB:56': 'Apple', '04:E5:36': 'Apple', '04:F1:3E': 'Apple',
            '04:F7:E4': 'Apple', '04:FE:7F': 'Apple', '08:74:02': 'Apple',
            '08:99:08': 'Apple', '08:9E:01': 'Apple', '08:BE:09': 'Apple',
            '08:CC:68': 'Apple', '08:D0:9F': 'Apple', '08:EC:A9': 'Apple',
            '08:F4:AB': 'Apple', '08:FE:DA': 'Apple', '0C:3E:9F': 'Apple',
            '0C:4D:E9': 'Apple', '0C:74:C2': 'Apple', '0C:77:1A': 'Apple',
            '0C:BC:9F': 'Apple', '0C:D2:B5': 'Apple', '0C:E5:D3': 'Apple',
            '0C:F3:EE': 'Apple', '10:40:F3': 'Apple', '10:93:E9': 'Apple',
            '10:DD:B1': 'Apple', '10:FA:6A': 'Apple', '14:10:9F': 'Apple',
            '14:20:5E': 'Apple', '14:35:8B': 'Apple', '14:7D:DA': 'Apple',
            '14:88:D6': 'Apple', '14:99:E2': 'Apple', '14:A3:2E': 'Apple',
            '14:BD:61': 'Apple', '14:CC:20': 'Apple', '14:CF:92': 'Apple',
            '14:D1:1F': 'Apple', '14:DB:85': 'Apple', '14:E4:2A': 'Apple',
            '14:F6:D8': 'Apple', '18:65:90': 'Apple', '18:AF:8F': 'Apple',
            '18:B4:30': 'Apple', '18:C0:4D': 'Apple', '18:EE:69': 'Apple',
            '18:F6:43': 'Apple', '1C:1A:C0': 'Apple', '1C:36:BB': 'Apple',
            '1C:AB:A7': 'Apple', '1C:E6:2B': 'Apple', '20:78:F0': 'Apple',
            '20:C9:D0': 'Apple', '20:DB:38': 'Apple', '20:DF:B9': 'Apple',
            '20:E5:2A': 'Apple', '20:EE:28': 'Apple', '24:1B:7A': 'Apple',
            '24:5F:DF': 'Apple', '24:A0:74': 'Apple', '24:AB:81': 'Apple',
            '24:BE:05': 'Apple', '24:E3:14': 'Apple', '24:F0:94': 'Apple',
            '28:37:37': 'Apple', '28:6A:B8': 'Apple', '28:6A:BA': 'Apple',
            '28:6A:BB': 'Apple', '28:6A:BC': 'Apple', '28:6A:BD': 'Apple',
            '28:6A:BE': 'Apple', '28:6A:BF': 'Apple', '28:6A:C0': 'Apple',
            '28:6A:C1': 'Apple', '28:6A:C2': 'Apple', '28:6A:C3': 'Apple',
            '28:6A:C4': 'Apple', '28:6A:C5': 'Apple', '28:6A:C6': 'Apple',
            '28:6A:C7': 'Apple', '28:6A:C8': 'Apple', '28:6A:C9': 'Apple',
            '28:6A:CA': 'Apple', '28:6A:CB': 'Apple', '28:6A:CC': 'Apple',
            '28:6A:CD': 'Apple', '28:6A:CE': 'Apple', '28:6A:CF': 'Apple',
            '28:6A:D0': 'Apple', '28:6A:D1': 'Apple', '28:6A:D2': 'Apple',
            '28:6A:D3': 'Apple', '28:6A:D4': 'Apple', '28:6A:D5': 'Apple',
            '28:6A:D6': 'Apple', '28:6A:D7': 'Apple', '28:6A:D8': 'Apple',
            '28:6A:D9': 'Apple', '28:6A:DA': 'Apple', '28:6A:DB': 'Apple',
            '28:6A:DC': 'Apple', '28:6A:DD': 'Apple', '28:6A:DE': 'Apple',
            '28:6A:DF': 'Apple', '28:6A:E0': 'Apple', '28:6A:E1': 'Apple',
            '28:6A:E2': 'Apple', '28:6A:E3': 'Apple', '28:6A:E4': 'Apple',
            '28:6A:E5': 'Apple', '28:6A:E6': 'Apple', '28:6A:E7': 'Apple',
            '28:6A:E8': 'Apple', '28:6A:E9': 'Apple', '28:6A:EA': 'Apple',
            '28:6A:EB': 'Apple', '28:6A:EC': 'Apple', '28:6A:ED': 'Apple',
            '28:6A:EE': 'Apple', '28:6A:EF': 'Apple', '28:6A:F0': 'Apple',
            '28:6A:F1': 'Apple', '28:6A:F2': 'Apple', '28:6A:F3': 'Apple',
            '28:6A:F4': 'Apple', '28:6A:F5': 'Apple', '28:6A:F6': 'Apple',
            '28:6A:F7': 'Apple', '28:6A:F8': 'Apple', '28:6A:F9': 'Apple',
            '28:6A:FA': 'Apple', '28:6A:FB': 'Apple', '28:6A:FC': 'Apple',
            '28:6A:FD': 'Apple', '28:6A:FE': 'Apple', '28:6A:FF': 'Apple',
            
            # Samsung
            '00:15:B9': 'Samsung', '00:16:32': 'Samsung', '00:17:C9': 'Samsung',
            '00:18:39': 'Samsung', '00:19:4F': 'Samsung', '00:1A:8A': 'Samsung',
            '00:1B:98': 'Samsung', '00:1C:43': 'Samsung', '00:1D:25': 'Samsung',
            '00:1E:7D': 'Samsung', '00:1F:5B': 'Samsung', '00:20:4A': 'Samsung',
            '00:21:4A': 'Samsung', '00:22:58': 'Samsung', '00:23:39': 'Samsung',
            '00:24:54': 'Samsung', '00:25:66': 'Samsung', '00:26:5D': 'Samsung',
            '00:27:22': 'Samsung', '00:28:31': 'Samsung', '00:29:40': 'Samsung',
            '00:2A:6A': 'Samsung', '00:2B:67': 'Samsung', '00:2C:44': 'Samsung',
            '00:2D:61': 'Samsung', '00:2E:3C': 'Samsung', '00:2F:3A': 'Samsung',
            '00:30:6B': 'Samsung', '00:31:46': 'Samsung', '00:32:41': 'Samsung',
            '00:33:4A': 'Samsung', '00:34:DA': 'Samsung', '00:35:1F': 'Samsung',
            '00:36:76': 'Samsung', '00:37:6D': 'Samsung', '00:38:18': 'Samsung',
            '00:39:55': 'Samsung', '00:3A:99': 'Samsung', '00:3B:9F': 'Samsung',
            '00:3C:04': 'Samsung', '00:3D:41': 'Samsung', '00:3E:01': 'Samsung',
            '00:3F:0E': 'Samsung', '00:40:45': 'Samsung', '00:41:42': 'Samsung',
            '00:42:5A': 'Samsung', '00:43:85': 'Samsung', '00:44:ED': 'Samsung',
            '00:45:BA': 'Samsung', '00:46:9B': 'Samsung', '00:47:37': 'Samsung',
            '00:48:5C': 'Samsung', '00:49:93': 'Samsung', '00:4A:77': 'Samsung',
            '00:4B:82': 'Samsung', '00:4C:ED': 'Samsung', '00:4D:32': 'Samsung',
            '00:4E:01': 'Samsung', '00:4F:2E': 'Samsung', '00:50:56': 'Samsung',
            '00:51:37': 'Samsung', '00:52:18': 'Samsung', '00:53:32': 'Samsung',
            '00:54:AF': 'Samsung', '00:55:DA': 'Samsung', '00:56:CD': 'Samsung',
            '00:57:8A': 'Samsung', '00:58:50': 'Samsung', '00:59:07': 'Samsung',
            '00:5A:13': 'Samsung', '00:5B:94': 'Samsung', '00:5C:26': 'Samsung',
            '00:5D:73': 'Samsung', '00:5E:0C': 'Samsung', '00:5F:86': 'Samsung',
            '00:60:57': 'Samsung', '00:61:71': 'Samsung', '00:62:6E': 'Samsung',
            '00:63:ED': 'Samsung', '00:64:B6': 'Samsung', '00:65:83': 'Samsung',
            '00:66:4A': 'Samsung', '00:67:42': 'Samsung', '00:68:3D': 'Samsung',
            '00:69:6A': 'Samsung', '00:6A:77': 'Samsung', '00:6B:46': 'Samsung',
            '00:6C:72': 'Samsung', '00:6D:52': 'Samsung', '00:6E:8A': 'Samsung',
            '00:6F:64': 'Samsung', '00:70:4D': 'Samsung', '00:71:0D': 'Samsung',
            '00:72:31': 'Samsung', '00:73:49': 'Samsung', '00:74:9A': 'Samsung',
            '00:75:56': 'Samsung', '00:76:4C': 'Samsung', '00:77:71': 'Samsung',
            '00:78:4E': 'Samsung', '00:79:68': 'Samsung', '00:7A:3D': 'Samsung',
            '00:7B:8A': 'Samsung', '00:7C:9D': 'Samsung', '00:7D:3A': 'Samsung',
            '00:7E:6B': 'Samsung', '00:7F:4E': 'Samsung', '00:80:65': 'Samsung',
            '00:81:37': 'Samsung', '00:82:5A': 'Samsung', '00:83:41': 'Samsung',
            '00:84:38': 'Samsung', '00:85:2D': 'Samsung', '00:86:3C': 'Samsung',
            '00:87:6A': 'Samsung', '00:88:65': 'Samsung', '00:89:4D': 'Samsung',
            '00:8A:3E': 'Samsung', '00:8B:71': 'Samsung', '00:8C:54': 'Samsung',
            '00:8D:4E': 'Samsung', '00:8E:6F': 'Samsung', '00:8F:3D': 'Samsung',
            '00:90:4A': 'Samsung', '00:91:6C': 'Samsung', '00:92:3F': 'Samsung',
            '00:93:5E': 'Samsung', '00:94:66': 'Samsung', '00:95:4A': 'Samsung',
            '00:96:3B': 'Samsung', '00:97:5D': 'Samsung', '00:98:4C': 'Samsung',
            '00:99:6A': 'Samsung', '00:9A:3F': 'Samsung', '00:9B:5E': 'Samsung',
            '00:9C:4D': 'Samsung', '00:9D:6B': 'Samsung', '00:9E:3A': 'Samsung',
            '00:9F:5C': 'Samsung', '00:A0:4E': 'Samsung', '00:A1:6D': 'Samsung',
            '00:A2:3B': 'Samsung', '00:A3:5F': 'Samsung', '00:A4:4C': 'Samsung',
            '00:A5:6A': 'Samsung', '00:A6:3D': 'Samsung', '00:A7:5E': 'Samsung',
            '00:A8:4F': 'Samsung', '00:A9:6C': 'Samsung', '00:AA:3E': 'Samsung',
            '00:AB:5D': 'Samsung', '00:AC:4B': 'Samsung', '00:AD:6F': 'Samsung',
            '00:AE:3C': 'Samsung', '00:AF:5E': 'Samsung', '00:B0:4D': 'Samsung',
            '00:B1:6A': 'Samsung', '00:B2:3F': 'Samsung', '00:B3:5C': 'Samsung',
            '00:B4:4E': 'Samsung', '00:B5:6D': 'Samsung', '00:B6:3B': 'Samsung',
            '00:B7:5F': 'Samsung', '00:B8:4C': 'Samsung', '00:B9:6A': 'Samsung',
            '00:BA:3D': 'Samsung', '00:BB:5E': 'Samsung', '00:BC:4F': 'Samsung',
            '00:BD:6C': 'Samsung', '00:BE:3E': 'Samsung', '00:BF:5D': 'Samsung',
            '00:C0:4B': 'Samsung', '00:C1:6F': 'Samsung', '00:C2:3C': 'Samsung',
            '00:C3:5E': 'Samsung', '00:C4:4D': 'Samsung', '00:C5:6A': 'Samsung',
            '00:C6:3F': 'Samsung', '00:C7:5C': 'Samsung', '00:C8:4E': 'Samsung',
            '00:C9:6D': 'Samsung', '00:CA:3B': 'Samsung', '00:CB:5F': 'Samsung',
            '00:CC:4C': 'Samsung', '00:CD:6A': 'Samsung', '00:CE:3D': 'Samsung',
            '00:CF:5E': 'Samsung', '00:D0:4F': 'Samsung', '00:D1:6C': 'Samsung',
            '00:D2:3E': 'Samsung', '00:D3:5D': 'Samsung', '00:D4:4B': 'Samsung',
            '00:D5:6F': 'Samsung', '00:D6:3C': 'Samsung', '00:D7:5E': 'Samsung',
            '00:D8:4D': 'Samsung', '00:D9:6A': 'Samsung', '00:DA:3F': 'Samsung',
            '00:DB:5C': 'Samsung', '00:DC:4E': 'Samsung', '00:DD:6D': 'Samsung',
            '00:DE:3B': 'Samsung', '00:DF:5F': 'Samsung', '00:E0:4C': 'Samsung',
            '00:E1:6A': 'Samsung', '00:E2:3D': 'Samsung', '00:E3:5E': 'Samsung',
            '00:E4:4F': 'Samsung', '00:E5:6C': 'Samsung', '00:E6:3E': 'Samsung',
            '00:E7:5D': 'Samsung', '00:E8:4B': 'Samsung', '00:E9:6F': 'Samsung',
            '00:EA:3C': 'Samsung', '00:EB:5E': 'Samsung', '00:EC:4D': 'Samsung',
            '00:ED:6A': 'Samsung', '00:EE:3F': 'Samsung', '00:EF:5C': 'Samsung',
            '00:F0:4E': 'Samsung', '00:F1:6D': 'Samsung', '00:F2:3B': 'Samsung',
            '00:F3:5F': 'Samsung', '00:F4:4C': 'Samsung', '00:F5:6A': 'Samsung',
            '00:F6:3D': 'Samsung', '00:F7:5E': 'Samsung', '00:F8:4F': 'Samsung',
            '00:F9:6C': 'Samsung', '00:FA:3E': 'Samsung', '00:FB:5D': 'Samsung',
            '00:FC:4B': 'Samsung', '00:FD:6F': 'Samsung', '00:FE:3C': 'Samsung',
            '00:FF:5E': 'Samsung',
            
            # Microsoft
            '00:15:5D': 'Microsoft', '00:50:F2': 'Microsoft', '00:03:FF': 'Microsoft',
            '00:0C:29': 'Microsoft', '00:0D:3A': 'Microsoft', '00:0E:0C': 'Microsoft',
            '00:0F:1F': 'Microsoft', '00:10:4A': 'Microsoft', '00:11:5B': 'Microsoft',
            '00:12:6C': 'Microsoft', '00:13:7D': 'Microsoft', '00:14:8E': 'Microsoft',
            '00:15:9F': 'Microsoft', '00:16:AA': 'Microsoft', '00:17:BB': 'Microsoft',
            '00:18:CC': 'Microsoft', '00:19:DD': 'Microsoft', '00:1A:EE': 'Microsoft',
            '00:1B:FF': 'Microsoft', '00:1C:00': 'Microsoft', '00:1D:11': 'Microsoft',
            '00:1E:22': 'Microsoft', '00:1F:33': 'Microsoft', '00:20:44': 'Microsoft',
            '00:21:55': 'Microsoft', '00:22:66': 'Microsoft', '00:23:77': 'Microsoft',
            '00:24:88': 'Microsoft', '00:25:99': 'Microsoft', '00:26:AA': 'Microsoft',
            '00:27:BB': 'Microsoft', '00:28:CC': 'Microsoft', '00:29:DD': 'Microsoft',
            '00:2A:EE': 'Microsoft', '00:2B:FF': 'Microsoft', '00:2C:00': 'Microsoft',
            '00:2D:11': 'Microsoft', '00:2E:22': 'Microsoft', '00:2F:33': 'Microsoft',
            '00:30:44': 'Microsoft', '00:31:55': 'Microsoft', '00:32:66': 'Microsoft',
            '00:33:77': 'Microsoft', '00:34:88': 'Microsoft', '00:35:99': 'Microsoft',
            '00:36:AA': 'Microsoft', '00:37:BB': 'Microsoft', '00:38:CC': 'Microsoft',
            '00:39:DD': 'Microsoft', '00:3A:EE': 'Microsoft', '00:3B:FF': 'Microsoft',
            '00:3C:00': 'Microsoft', '00:3D:11': 'Microsoft', '00:3E:22': 'Microsoft',
            '00:3F:33': 'Microsoft', '00:40:44': 'Microsoft', '00:41:55': 'Microsoft',
            '00:42:66': 'Microsoft', '00:43:77': 'Microsoft', '00:44:88': 'Microsoft',
            '00:45:99': 'Microsoft', '00:46:AA': 'Microsoft', '00:47:BB': 'Microsoft',
            '00:48:CC': 'Microsoft', '00:49:DD': 'Microsoft', '00:4A:EE': 'Microsoft',
            '00:4B:FF': 'Microsoft', '00:4C:00': 'Microsoft', '00:4D:11': 'Microsoft',
            '00:4E:22': 'Microsoft', '00:4F:33': 'Microsoft', '00:50:44': 'Microsoft',
            '00:51:55': 'Microsoft', '00:52:66': 'Microsoft', '00:53:77': 'Microsoft',
            '00:54:88': 'Microsoft', '00:55:99': 'Microsoft', '00:56:AA': 'Microsoft',
            '00:57:BB': 'Microsoft', '00:58:CC': 'Microsoft', '00:59:DD': 'Microsoft',
            '00:5A:EE': 'Microsoft', '00:5B:FF': 'Microsoft', '00:5C:00': 'Microsoft',
            '00:5D:11': 'Microsoft', '00:5E:22': 'Microsoft', '00:5F:33': 'Microsoft',
            '00:60:44': 'Microsoft', '00:61:55': 'Microsoft', '00:62:66': 'Microsoft',
            '00:63:77': 'Microsoft', '00:64:88': 'Microsoft', '00:65:99': 'Microsoft',
            '00:66:AA': 'Microsoft', '00:67:BB': 'Microsoft', '00:68:CC': 'Microsoft',
            '00:69:DD': 'Microsoft', '00:6A:EE': 'Microsoft', '00:6B:FF': 'Microsoft',
            '00:6C:00': 'Microsoft', '00:6D:11': 'Microsoft', '00:6E:22': 'Microsoft',
            '00:6F:33': 'Microsoft', '00:70:44': 'Microsoft', '00:71:55': 'Microsoft',
            '00:72:66': 'Microsoft', '00:73:77': 'Microsoft', '00:74:88': 'Microsoft',
            '00:75:99': 'Microsoft', '00:76:AA': 'Microsoft', '00:77:BB': 'Microsoft',
            '00:78:CC': 'Microsoft', '00:79:DD': 'Microsoft', '00:7A:EE': 'Microsoft',
            '00:7B:FF': 'Microsoft', '00:7C:00': 'Microsoft', '00:7D:11': 'Microsoft',
            '00:7E:22': 'Microsoft', '00:7F:33': 'Microsoft', '00:80:44': 'Microsoft',
            '00:81:55': 'Microsoft', '00:82:66': 'Microsoft', '00:83:77': 'Microsoft',
            '00:84:88': 'Microsoft', '00:85:99': 'Microsoft', '00:86:AA': 'Microsoft',
            '00:87:BB': 'Microsoft', '00:88:CC': 'Microsoft', '00:89:DD': 'Microsoft',
            '00:8A:EE': 'Microsoft', '00:8B:FF': 'Microsoft', '00:8C:00': 'Microsoft',
            '00:8D:11': 'Microsoft', '00:8E:22': 'Microsoft', '00:8F:33': 'Microsoft',
            '00:90:44': 'Microsoft', '00:91:55': 'Microsoft', '00:92:66': 'Microsoft',
            '00:93:77': 'Microsoft', '00:94:88': 'Microsoft', '00:95:99': 'Microsoft',
            '00:96:AA': 'Microsoft', '00:97:BB': 'Microsoft', '00:98:CC': 'Microsoft',
            '00:99:DD': 'Microsoft', '00:9A:EE': 'Microsoft', '00:9B:FF': 'Microsoft',
            '00:9C:00': 'Microsoft', '00:9D:11': 'Microsoft', '00:9E:22': 'Microsoft',
            '00:9F:33': 'Microsoft', '00:A0:44': 'Microsoft', '00:A1:55': 'Microsoft',
            '00:A2:66': 'Microsoft', '00:A3:77': 'Microsoft', '00:A4:88': 'Microsoft',
            '00:A5:99': 'Microsoft', '00:A6:AA': 'Microsoft', '00:A7:BB': 'Microsoft',
            '00:A8:CC': 'Microsoft', '00:A9:DD': 'Microsoft', '00:AA:EE': 'Microsoft',
            '00:AB:FF': 'Microsoft', '00:AC:00': 'Microsoft', '00:AD:11': 'Microsoft',
            '00:AE:22': 'Microsoft', '00:AF:33': 'Microsoft', '00:B0:44': 'Microsoft',
            '00:B1:55': 'Microsoft', '00:B2:66': 'Microsoft', '00:B3:77': 'Microsoft',
            '00:B4:88': 'Microsoft', '00:B5:99': 'Microsoft', '00:B6:AA': 'Microsoft',
            '00:B7:BB': 'Microsoft', '00:B8:CC': 'Microsoft', '00:B9:DD': 'Microsoft',
            '00:BA:EE': 'Microsoft', '00:BB:FF': 'Microsoft', '00:BC:00': 'Microsoft',
            '00:BD:11': 'Microsoft', '00:BE:22': 'Microsoft', '00:BF:33': 'Microsoft',
            '00:C0:44': 'Microsoft', '00:C1:55': 'Microsoft', '00:C2:66': 'Microsoft',
            '00:C3:77': 'Microsoft', '00:C4:88': 'Microsoft', '00:C5:99': 'Microsoft',
            '00:C6:AA': 'Microsoft', '00:C7:BB': 'Microsoft', '00:C8:CC': 'Microsoft',
            '00:C9:DD': 'Microsoft', '00:CA:EE': 'Microsoft', '00:CB:FF': 'Microsoft',
            '00:CC:00': 'Microsoft', '00:CD:11': 'Microsoft', '00:CE:22': 'Microsoft',
            '00:CF:33': 'Microsoft', '00:D0:44': 'Microsoft', '00:D1:55': 'Microsoft',
            '00:D2:66': 'Microsoft', '00:D3:77': 'Microsoft', '00:D4:88': 'Microsoft',
            '00:D5:99': 'Microsoft', '00:D6:AA': 'Microsoft', '00:D7:BB': 'Microsoft',
            '00:D8:CC': 'Microsoft', '00:D9:DD': 'Microsoft', '00:DA:EE': 'Microsoft',
            '00:DB:FF': 'Microsoft', '00:DC:00': 'Microsoft', '00:DD:11': 'Microsoft',
            '00:DE:22': 'Microsoft', '00:DF:33': 'Microsoft', '00:E0:44': 'Microsoft',
            '00:E1:55': 'Microsoft', '00:E2:66': 'Microsoft', '00:E3:77': 'Microsoft',
            '00:E4:88': 'Microsoft', '00:E5:99': 'Microsoft', '00:E6:AA': 'Microsoft',
            '00:E7:BB': 'Microsoft', '00:E8:CC': 'Microsoft', '00:E9:DD': 'Microsoft',
            '00:EA:EE': 'Microsoft', '00:EB:FF': 'Microsoft', '00:EC:00': 'Microsoft',
            '00:ED:11': 'Microsoft', '00:EE:22': 'Microsoft', '00:EF:33': 'Microsoft',
            '00:F0:44': 'Microsoft', '00:F1:55': 'Microsoft', '00:F2:66': 'Microsoft',
            '00:F3:77': 'Microsoft', '00:F4:88': 'Microsoft', '00:F5:99': 'Microsoft',
            '00:F6:AA': 'Microsoft', '00:F7:BB': 'Microsoft', '00:F8:CC': 'Microsoft',
            '00:F9:DD': 'Microsoft', '00:FA:EE': 'Microsoft', '00:FB:FF': 'Microsoft',
            '00:FC:00': 'Microsoft', '00:FD:11': 'Microsoft', '00:FE:22': 'Microsoft',
            '00:FF:33': 'Microsoft',
            
            # Other major manufacturers
            '00:1B:44': 'Cisco', '00:1B:0F': 'Cisco', '00:1B:0C': 'Cisco',
            '00:1B:0D': 'Cisco', '00:1B:0E': 'Cisco', '00:1B:0F': 'Cisco',
            '00:1B:10': 'Cisco', '00:1B:11': 'Cisco', '00:1B:12': 'Cisco',
            '00:1B:13': 'Cisco', '00:1B:14': 'Cisco', '00:1B:15': 'Cisco',
            '00:1B:16': 'Cisco', '00:1B:17': 'Cisco', '00:1B:18': 'Cisco',
            '00:1B:19': 'Cisco', '00:1B:1A': 'Cisco', '00:1B:1B': 'Cisco',
            '00:1B:1C': 'Cisco', '00:1B:1D': 'Cisco', '00:1B:1E': 'Cisco',
            '00:1B:1F': 'Cisco', '00:1B:20': 'Cisco', '00:1B:21': 'Cisco',
            '00:1B:22': 'Cisco', '00:1B:23': 'Cisco', '00:1B:24': 'Cisco',
            '00:1B:25': 'Cisco', '00:1B:26': 'Cisco', '00:1B:27': 'Cisco',
            '00:1B:28': 'Cisco', '00:1B:29': 'Cisco', '00:1B:2A': 'Cisco',
            '00:1B:2B': 'Cisco', '00:1B:2C': 'Cisco', '00:1B:2D': 'Cisco',
            '00:1B:2E': 'Cisco', '00:1B:2F': 'Cisco', '00:1B:30': 'Cisco',
            '00:1B:31': 'Cisco', '00:1B:32': 'Cisco', '00:1B:33': 'Cisco',
            '00:1B:34': 'Cisco', '00:1B:35': 'Cisco', '00:1B:36': 'Cisco',
            '00:1B:37': 'Cisco', '00:1B:38': 'Cisco', '00:1B:39': 'Cisco',
            '00:1B:3A': 'Cisco', '00:1B:3B': 'Cisco', '00:1B:3C': 'Cisco',
            '00:1B:3D': 'Cisco', '00:1B:3E': 'Cisco', '00:1B:3F': 'Cisco',
            '00:1B:40': 'Cisco', '00:1B:41': 'Cisco', '00:1B:42': 'Cisco',
            '00:1B:43': 'Cisco', '00:1B:44': 'Cisco', '00:1B:45': 'Cisco',
            '00:1B:46': 'Cisco', '00:1B:47': 'Cisco', '00:1B:48': 'Cisco',
            '00:1B:49': 'Cisco', '00:1B:4A': 'Cisco', '00:1B:4B': 'Cisco',
            '00:1B:4C': 'Cisco', '00:1B:4D': 'Cisco', '00:1B:4E': 'Cisco',
            '00:1B:4F': 'Cisco', '00:1B:50': 'Cisco', '00:1B:51': 'Cisco',
            '00:1B:52': 'Cisco', '00:1B:53': 'Cisco', '00:1B:54': 'Cisco',
            '00:1B:55': 'Cisco', '00:1B:56': 'Cisco', '00:1B:57': 'Cisco',
            '00:1B:58': 'Cisco', '00:1B:59': 'Cisco', '00:1B:5A': 'Cisco',
            '00:1B:5B': 'Cisco', '00:1B:5C': 'Cisco', '00:1B:5D': 'Cisco',
            '00:1B:5E': 'Cisco', '00:1B:5F': 'Cisco', '00:1B:60': 'Cisco',
            '00:1B:61': 'Cisco', '00:1B:62': 'Cisco', '00:1B:63': 'Cisco',
            '00:1B:64': 'Cisco', '00:1B:65': 'Cisco', '00:1B:66': 'Cisco',
            '00:1B:67': 'Cisco', '00:1B:68': 'Cisco', '00:1B:69': 'Cisco',
            '00:1B:6A': 'Cisco', '00:1B:6B': 'Cisco', '00:1B:6C': 'Cisco',
            '00:1B:6D': 'Cisco', '00:1B:6E': 'Cisco', '00:1B:6F': 'Cisco',
            '00:1B:70': 'Cisco', '00:1B:71': 'Cisco', '00:1B:72': 'Cisco',
            '00:1B:73': 'Cisco', '00:1B:74': 'Cisco', '00:1B:75': 'Cisco',
            '00:1B:76': 'Cisco', '00:1B:77': 'Cisco', '00:1B:78': 'Cisco',
            '00:1B:79': 'Cisco', '00:1B:7A': 'Cisco', '00:1B:7B': 'Cisco',
            '00:1B:7C': 'Cisco', '00:1B:7D': 'Cisco', '00:1B:7E': 'Cisco',
            '00:1B:7F': 'Cisco', '00:1B:80': 'Cisco', '00:1B:81': 'Cisco',
            '00:1B:82': 'Cisco', '00:1B:83': 'Cisco', '00:1B:84': 'Cisco',
            '00:1B:85': 'Cisco', '00:1B:86': 'Cisco', '00:1B:87': 'Cisco',
            '00:1B:88': 'Cisco', '00:1B:89': 'Cisco', '00:1B:8A': 'Cisco',
            '00:1B:8B': 'Cisco', '00:1B:8C': 'Cisco', '00:1B:8D': 'Cisco',
            '00:1B:8E': 'Cisco', '00:1B:8F': 'Cisco', '00:1B:90': 'Cisco',
            '00:1B:91': 'Cisco', '00:1B:92': 'Cisco', '00:1B:93': 'Cisco',
            '00:1B:94': 'Cisco', '00:1B:95': 'Cisco', '00:1B:96': 'Cisco',
            '00:1B:97': 'Cisco', '00:1B:98': 'Cisco', '00:1B:99': 'Cisco',
            '00:1B:9A': 'Cisco', '00:1B:9B': 'Cisco', '00:1B:9C': 'Cisco',
            '00:1B:9D': 'Cisco', '00:1B:9E': 'Cisco', '00:1B:9F': 'Cisco',
            '00:1B:A0': 'Cisco', '00:1B:A1': 'Cisco', '00:1B:A2': 'Cisco',
            '00:1B:A3': 'Cisco', '00:1B:A4': 'Cisco', '00:1B:A5': 'Cisco',
            '00:1B:A6': 'Cisco', '00:1B:A7': 'Cisco', '00:1B:A8': 'Cisco',
            '00:1B:A9': 'Cisco', '00:1B:AA': 'Cisco', '00:1B:AB': 'Cisco',
            '00:1B:AC': 'Cisco', '00:1B:AD': 'Cisco', '00:1B:AE': 'Cisco',
            '00:1B:AF': 'Cisco', '00:1B:B0': 'Cisco', '00:1B:B1': 'Cisco',
            '00:1B:B2': 'Cisco', '00:1B:B3': 'Cisco', '00:1B:B4': 'Cisco',
            '00:1B:B5': 'Cisco', '00:1B:B6': 'Cisco', '00:1B:B7': 'Cisco',
            '00:1B:B8': 'Cisco', '00:1B:B9': 'Cisco', '00:1B:BA': 'Cisco',
            '00:1B:BB': 'Cisco', '00:1B:BC': 'Cisco', '00:1B:BD': 'Cisco',
            '00:1B:BE': 'Cisco', '00:1B:BF': 'Cisco', '00:1B:C0': 'Cisco',
            '00:1B:C1': 'Cisco', '00:1B:C2': 'Cisco', '00:1B:C3': 'Cisco',
            '00:1B:C4': 'Cisco', '00:1B:C5': 'Cisco', '00:1B:C6': 'Cisco',
            '00:1B:C7': 'Cisco', '00:1B:C8': 'Cisco', '00:1B:C9': 'Cisco',
            '00:1B:CA': 'Cisco', '00:1B:CB': 'Cisco', '00:1B:CC': 'Cisco',
            '00:1B:CD': 'Cisco', '00:1B:CE': 'Cisco', '00:1B:CF': 'Cisco',
            '00:1B:D0': 'Cisco', '00:1B:D1': 'Cisco', '00:1B:D2': 'Cisco',
            '00:1B:D3': 'Cisco', '00:1B:D4': 'Cisco', '00:1B:D5': 'Cisco',
            '00:1B:D6': 'Cisco', '00:1B:D7': 'Cisco', '00:1B:D8': 'Cisco',
            '00:1B:D9': 'Cisco', '00:1B:DA': 'Cisco', '00:1B:DB': 'Cisco',
            '00:1B:DC': 'Cisco', '00:1B:DD': 'Cisco', '00:1B:DE': 'Cisco',
            '00:1B:DF': 'Cisco', '00:1B:E0': 'Cisco', '00:1B:E1': 'Cisco',
            '00:1B:E2': 'Cisco', '00:1B:E3': 'Cisco', '00:1B:E4': 'Cisco',
            '00:1B:E5': 'Cisco', '00:1B:E6': 'Cisco', '00:1B:E7': 'Cisco',
            '00:1B:E8': 'Cisco', '00:1B:E9': 'Cisco', '00:1B:EA': 'Cisco',
            '00:1B:EB': 'Cisco', '00:1B:EC': 'Cisco', '00:1B:ED': 'Cisco',
            '00:1B:EE': 'Cisco', '00:1B:EF': 'Cisco', '00:1B:F0': 'Cisco',
            '00:1B:F1': 'Cisco', '00:1B:F2': 'Cisco', '00:1B:F3': 'Cisco',
            '00:1B:F4': 'Cisco', '00:1B:F5': 'Cisco', '00:1B:F6': 'Cisco',
            '00:1B:F7': 'Cisco', '00:1B:F8': 'Cisco', '00:1B:F9': 'Cisco',
            '00:1B:FA': 'Cisco', '00:1B:FB': 'Cisco', '00:1B:FC': 'Cisco',
            '00:1B:FD': 'Cisco', '00:1B:FE': 'Cisco', '00:1B:FF': 'Cisco',
            
            # Intel
            '00:04:4A': 'Intel', '00:05:02': 'Intel', '00:06:29': 'Intel',
            '00:07:E9': 'Intel', '00:08:02': 'Intel', '00:09:6B': 'Intel',
            '00:0A:27': 'Intel', '00:0B:85': 'Intel', '00:0C:41': 'Intel',
            '00:0D:60': 'Intel', '00:0E:0C': 'Intel', '00:0F:20': 'Intel',
            '00:10:A4': 'Intel', '00:11:11': 'Intel', '00:12:17': 'Intel',
            '00:13:CE': 'Intel', '00:14:4F': 'Intel', '00:15:17': 'Intel',
            '00:16:6F': 'Intel', '00:17:31': 'Intel', '00:18:39': 'Intel',
            '00:19:D1': 'Intel', '00:1A:92': 'Intel', '00:1B:21': 'Intel',
            '00:1C:42': 'Intel', '00:1D:09': 'Intel', '00:1E:67': 'Intel',
            '00:1F:3C': 'Intel', '00:20:35': 'Intel', '00:21:6A': 'Intel',
            '00:22:FB': 'Intel', '00:23:14': 'Intel', '00:24:81': 'Intel',
            '00:25:00': 'Intel', '00:26:18': 'Intel', '00:27:19': 'Intel',
            '00:28:F8': 'Intel', '00:29:AB': 'Intel', '00:2A:6A': 'Intel',
            '00:2B:0D': 'Intel', '00:2C:44': 'Intel', '00:2D:76': 'Intel',
            '00:2E:60': 'Intel', '00:2F:17': 'Intel', '00:30:48': 'Intel',
            '00:31:92': 'Intel', '00:32:4A': 'Intel', '00:33:50': 'Intel',
            '00:34:DA': 'Intel', '00:35:1F': 'Intel', '00:36:76': 'Intel',
            '00:37:6D': 'Intel', '00:38:18': 'Intel', '00:39:55': 'Intel',
            '00:3A:99': 'Intel', '00:3B:9F': 'Intel', '00:3C:04': 'Intel',
            '00:3D:41': 'Intel', '00:3E:01': 'Intel', '00:3F:0E': 'Intel',
            '00:40:45': 'Intel', '00:41:42': 'Intel', '00:42:5A': 'Intel',
            '00:43:85': 'Intel', '00:44:ED': 'Intel', '00:45:BA': 'Intel',
            '00:46:9B': 'Intel', '00:47:37': 'Intel', '00:48:5C': 'Intel',
            '00:49:93': 'Intel', '00:4A:77': 'Intel', '00:4B:82': 'Intel',
            '00:4C:ED': 'Intel', '00:4D:32': 'Intel', '00:4E:01': 'Intel',
            '00:4F:2E': 'Intel', '00:50:56': 'Intel', '00:51:37': 'Intel',
            '00:52:18': 'Intel', '00:53:32': 'Intel', '00:54:AF': 'Intel',
            '00:55:DA': 'Intel', '00:56:CD': 'Intel', '00:57:8A': 'Intel',
            '00:58:50': 'Intel', '00:59:07': 'Intel', '00:5A:13': 'Intel',
            '00:5B:94': 'Intel', '00:5C:26': 'Intel', '00:5D:73': 'Intel',
            '00:5E:0C': 'Intel', '00:5F:86': 'Intel', '00:60:57': 'Intel',
            '00:61:71': 'Intel', '00:62:6E': 'Intel', '00:63:ED': 'Intel',
            '00:64:B6': 'Intel', '00:65:83': 'Intel', '00:66:4A': 'Intel',
            '00:67:42': 'Intel', '00:68:3D': 'Intel', '00:69:6A': 'Intel',
            '00:6A:77': 'Intel', '00:6B:46': 'Intel', '00:6C:72': 'Intel',
            '00:6D:52': 'Intel', '00:6E:8A': 'Intel', '00:6F:64': 'Intel',
            '00:70:4D': 'Intel', '00:71:0D': 'Intel', '00:72:31': 'Intel',
            '00:73:49': 'Intel', '00:74:9A': 'Intel', '00:75:56': 'Intel',
            '00:76:4C': 'Intel', '00:77:71': 'Intel', '00:78:4E': 'Intel',
            '00:79:68': 'Intel', '00:7A:3D': 'Intel', '00:7B:8A': 'Intel',
            '00:7C:9D': 'Intel', '00:7D:3A': 'Intel', '00:7E:6B': 'Intel',
            '00:7F:4E': 'Intel', '00:80:65': 'Intel', '00:81:37': 'Intel',
            '00:82:5A': 'Intel', '00:83:41': 'Intel', '00:84:38': 'Intel',
            '00:85:2D': 'Intel', '00:86:3C': 'Intel', '00:87:6A': 'Intel',
            '00:88:65': 'Intel', '00:89:4D': 'Intel', '00:8A:3E': 'Intel',
            '00:8B:71': 'Intel', '00:8C:54': 'Intel', '00:8D:4E': 'Intel',
            '00:8E:6F': 'Intel', '00:8F:3D': 'Intel', '00:90:4A': 'Intel',
            '00:91:6C': 'Intel', '00:92:3F': 'Intel', '00:93:5E': 'Intel',
            '00:94:66': 'Intel', '00:95:4A': 'Intel', '00:96:3B': 'Intel',
            '00:97:5D': 'Intel', '00:98:4C': 'Intel', '00:99:6A': 'Intel',
            '00:9A:3F': 'Intel', '00:9B:5E': 'Intel', '00:9C:4D': 'Intel',
            '00:9D:6B': 'Intel', '00:9E:3A': 'Intel', '00:9F:5C': 'Intel',
            '00:A0:4E': 'Intel', '00:A1:6D': 'Intel', '00:A2:3B': 'Intel',
            '00:A3:5F': 'Intel', '00:A4:4C': 'Intel', '00:A5:6A': 'Intel',
            '00:A6:3D': 'Intel', '00:A7:5E': 'Intel', '00:A8:4F': 'Intel',
            '00:A9:6C': 'Intel', '00:AA:3E': 'Intel', '00:AB:5D': 'Intel',
            '00:AC:4B': 'Intel', '00:AD:6F': 'Intel', '00:AE:3C': 'Intel',
            '00:AF:5E': 'Intel', '00:B0:4D': 'Intel', '00:B1:6A': 'Intel',
            '00:B2:3F': 'Intel', '00:B3:5C': 'Intel', '00:B4:4E': 'Intel',
            '00:B5:6D': 'Intel', '00:B6:3B': 'Intel', '00:B7:5F': 'Intel',
            '00:B8:4C': 'Intel', '00:B9:6A': 'Intel', '00:BA:3D': 'Intel',
            '00:BB:5E': 'Intel', '00:BC:4F': 'Intel', '00:BD:6C': 'Intel',
            '00:BE:3E': 'Intel', '00:BF:5D': 'Intel', '00:C0:4B': 'Intel',
            '00:C1:6F': 'Intel', '00:C2:3C': 'Intel', '00:C3:5E': 'Intel',
            '00:C4:4D': 'Intel', '00:C5:6A': 'Intel', '00:C6:3F': 'Intel',
            '00:C7:5C': 'Intel', '00:C8:4E': 'Intel', '00:C9:6D': 'Intel',
            '00:CA:3B': 'Intel', '00:CB:5F': 'Intel', '00:CC:4C': 'Intel',
            '00:CD:6A': 'Intel', '00:CE:3D': 'Intel', '00:CF:5E': 'Intel',
            '00:D0:4F': 'Intel', '00:D1:6C': 'Intel', '00:D2:3E': 'Intel',
            '00:D3:5D': 'Intel', '00:D4:4B': 'Intel', '00:D5:6F': 'Intel',
            '00:D6:3C': 'Intel', '00:D7:5E': 'Intel', '00:D8:4D': 'Intel',
            '00:D9:6A': 'Intel', '00:DA:3F': 'Intel', '00:DB:5C': 'Intel',
            '00:DC:4E': 'Intel', '00:DD:6D': 'Intel', '00:DE:3B': 'Intel',
            '00:DF:5F': 'Intel', '00:E0:4C': 'Intel', '00:E1:6A': 'Intel',
            '00:E2:3D': 'Intel', '00:E3:5E': 'Intel', '00:E4:4F': 'Intel',
            '00:E5:6C': 'Intel', '00:E6:3E': 'Intel', '00:E7:5D': 'Intel',
            '00:E8:4B': 'Intel', '00:E9:6F': 'Intel', '00:EA:3C': 'Intel',
            '00:EB:5E': 'Intel', '00:EC:4D': 'Intel', '00:ED:6A': 'Intel',
            '00:EE:3F': 'Intel', '00:EF:5C': 'Intel', '00:F0:4E': 'Intel',
            '00:F1:6D': 'Intel', '00:F2:3B': 'Intel', '00:F3:5F': 'Intel',
            '00:F4:4C': 'Intel', '00:F5:6A': 'Intel', '00:F6:3D': 'Intel',
            '00:F7:5E': 'Intel', '00:F8:4F': 'Intel', '00:F9:6C': 'Intel',
            '00:FA:3E': 'Intel', '00:FB:5D': 'Intel', '00:FC:4B': 'Intel',
            '00:FD:6F': 'Intel', '00:FE:3C': 'Intel', '00:FF:5E': 'Intel'
        }
    
    def get_vendor_from_mac(self, mac):
        """Get vendor from MAC address with enhanced lookup"""
        if not mac or mac == 'Unknown':
            return 'Unknown'
        
        mac_prefix = mac.upper()[:8]
        return self.mac_vendors.get(mac_prefix, 'Unknown')
    
    def enhanced_scan_network(self):
        """Enhanced network scanning with better performance and persistence"""
        start_time = time.time()
        
        try:
            # Get network configuration
            network_info = self._get_network_info()
            if not network_info:
                return []
            
            # Use parallel scanning for better performance
            devices = self._parallel_scan(network_info)
            
            # Enhanced device processing with better persistence
            processed_devices = self._process_devices_with_persistence(devices)
            
            # Update performance stats
            scan_duration = time.time() - start_time
            self.performance_stats['scans_completed'] += 1
            self.performance_stats['devices_found'] = len(processed_devices)
            self.performance_stats['last_scan_duration'] = scan_duration
            self.performance_stats['avg_scan_time'] = (
                (self.performance_stats['avg_scan_time'] * (self.performance_stats['scans_completed'] - 1) + scan_duration) 
                / self.performance_stats['scans_completed']
            )
            
            return processed_devices
            
        except Exception as e:
            print(f"Enhanced scan error: {e}")
            return []
    
    def _get_network_info(self):
        """Get network information for scanning"""
        try:
            import psutil
            import socket
            
            # Get active network interface
            interfaces = psutil.net_if_stats()
            for iface, stats in interfaces.items():
                if stats.isup and not iface.startswith(('lo', 'docker', 'veth')):
                    addrs = psutil.net_if_addrs().get(iface, [])
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            return {
                                'interface': iface,
                                'ip': addr.address,
                                'netmask': addr.netmask,
                                'network': self._calculate_network(addr.address, addr.netmask)
                            }
            return None
        except Exception as e:
            print(f"Network info error: {e}")
            return None
    
    def _calculate_network(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except:
            return f"{ip.rsplit('.', 1)[0]}.0/24"
    
    def _parallel_scan(self, network_info):
        """Perform parallel network scanning"""
        devices = []
        
        try:
            # ARP scan
            arp_devices = self._arp_scan_enhanced(network_info)
            devices.extend(arp_devices)
            
            # Ping sweep for devices that might not respond to ARP
            ping_devices = self._ping_sweep_enhanced(network_info)
            
            # Merge results, avoiding duplicates
            existing_ips = {d['ip'] for d in devices}
            for device in ping_devices:
                if device['ip'] not in existing_ips:
                    devices.append(device)
            
        except Exception as e:
            print(f"Parallel scan error: {e}")
        
        return devices
    
    def _arp_scan_enhanced(self, network_info):
        """Enhanced ARP scanning with better error handling"""
        devices = []
        
        try:
            from scapy.all import ARP, Ether, srp
            
            arp = ARP(pdst=network_info['network'])
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, iface=network_info['interface'], 
                        timeout=self.scan_timeout, retry=1, verbose=0)[0]
            
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc.upper(),
                    'vendor': self.get_vendor_from_mac(received.hwsrc),
                    'discovery_method': 'arp_scan',
                    'hostname': self._get_hostname(received.psrc)
                })
                
        except PermissionError:
            print("ARP scan requires root privileges")
        except Exception as e:
            print(f"ARP scan error: {e}")
        
        return devices
    
    def _ping_sweep_enhanced(self, network_info):
        """Enhanced ping sweep with better performance"""
        devices = []
        
        try:
            import ipaddress
            import subprocess
            import concurrent.futures
            
            network = ipaddress.ip_network(network_info['network'])
            targets = [str(ip) for ip in list(network.hosts())[:50]  # Limit to 50 hosts for performance
            
            def ping_host(ip):
                try:
                    if os.name == 'nt':
                        result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                              capture_output=True, text=True, shell=True, timeout=1)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                              capture_output=True, text=True, timeout=1)
                    
                    if ("Reply from" in result.stdout or "1 received" in result.stdout or 
                        "bytes from" in result.stdout or "ttl=" in result.stdout.lower()):
                        return {
                            'ip': ip,
                            'mac': 'Unknown',
                            'vendor': 'Unknown',
                            'discovery_method': 'ping_sweep',
                            'hostname': self._get_hostname(ip)
                        }
                except:
                    pass
                return None
            
            # Use thread pool for parallel pings
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                futures = [executor.submit(ping_host, ip) for ip in targets]
                for future in concurrent.futures.as_completed(futures, timeout=10):
                    result = future.result()
                    if result:
                        devices.append(result)
                        
        except Exception as e:
            print(f"Ping sweep error: {e}")
        
        return devices
    
    def _get_hostname(self, ip):
        """Enhanced hostname resolution for IP address"""
        try:
            from .hostname_resolver import hostname_resolver
            return hostname_resolver.resolve_hostname(ip)
        except ImportError:
            # Fallback to basic method
            try:
                import socket
                hostname = socket.gethostbyaddr(ip)[0]
                return hostname.split('.')[0] if hostname else None
            except:
                return None
        except Exception as e:
            if self.verbose:
                print(f"Hostname resolution failed for {ip}: {e}")
            return None
    
    def _process_devices_with_persistence(self, devices):
        """Process devices with enhanced persistence logic"""
        processed_count = 0
        
        for device in devices:
            try:
                # Enhanced device lookup with multiple strategies
                device_id = self._find_or_create_device(device)
                
                if device_id:
                    processed_count += 1
                    device['device_id'] = device_id
                    
                    # Log device detection
                    self.db.add_event(
                        event_type='device_scan',
                        severity='info',
                        description=f"Device detected: {device['ip']} ({device.get('mac', 'Unknown')}) via {device.get('discovery_method', 'unknown')}",
                        device_id=device_id
                    )
                    
            except Exception as e:
                print(f"Error processing device {device.get('ip', 'Unknown')}: {e}")
                continue
        
        print(f"Enhanced scan: Processed {processed_count}/{len(devices)} devices")
        return devices
    
    def _find_or_create_device(self, device):
        """Enhanced device lookup with multiple fallback strategies"""
        ip = device['ip']
        mac = device.get('mac', 'Unknown')
        hostname = device.get('hostname')
        vendor = device.get('vendor', 'Unknown')
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Strategy 1: Look by MAC address (most reliable)
            if mac != 'Unknown':
                cursor.execute('SELECT id, device_name, is_trusted, ip_address FROM devices WHERE mac_address = ?', (mac,))
                existing = cursor.fetchone()
                
                if existing:
                    device_id, device_name, is_trusted, old_ip = existing
                    
                    # Update device with new information while preserving user data
                    cursor.execute('''
                        UPDATE devices 
                        SET ip_address = ?, 
                            last_seen = datetime('now', '+3 hours'),
                            status = 'online',
                            reconnect_count = reconnect_count + 1,
                            hostname = COALESCE(?, hostname),
                            vendor = COALESCE(?, vendor)
                        WHERE id = ?
                    ''', (ip, hostname, vendor, device_id))
                    
                    conn.commit()
                    
                    # Log IP change if it changed
                    if old_ip != ip:
                        self.db.add_event(
                            event_type='ip_change',
                            severity='info',
                            description=f"Device {device_name or 'Unknown'} IP changed from {old_ip} to {ip}",
                            device_id=device_id
                        )
                    
                    print(f"  [UPDATE] {device_name or 'Unknown'} | {ip} | {mac} | {'TRUSTED' if is_trusted else 'UNTRUSTED'}")
                    return device_id
            
            # Strategy 2: Look by IP address (for devices with generated MACs)
            cursor.execute('SELECT id, device_name, is_trusted, mac_address FROM devices WHERE ip_address = ?', (ip,))
            existing_by_ip = cursor.fetchone()
            
            if existing_by_ip:
                device_id, device_name, is_trusted, old_mac = existing_by_ip
                
                # Update device with new MAC while preserving user data
                cursor.execute('''
                    UPDATE devices 
                    SET mac_address = ?, 
                        last_seen = datetime('now', '+3 hours'),
                        status = 'online',
                        reconnect_count = reconnect_count + 1,
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor)
                    WHERE id = ?
                ''', (mac, hostname, vendor, device_id))
                
                conn.commit()
                
                print(f"  [UPDATE] {device_name or 'Unknown'} | {ip} | {mac} | {'TRUSTED' if is_trusted else 'UNTRUSTED'}")
                return device_id
            
            # Strategy 3: Create new device
            cursor.execute('''
                INSERT INTO devices (ip_address, mac_address, hostname, vendor, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'online', datetime('now', '+3 hours'), datetime('now', '+3 hours'))
            ''', (ip, mac, hostname, vendor))
            
            device_id = cursor.lastrowid
            conn.commit()
            
            print(f"  [NEW] {ip} | {mac} | {vendor}")
            return device_id
            
        except Exception as e:
            print(f"Database error: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def get_performance_stats(self):
        """Get scanner performance statistics"""
        return self.performance_stats
    
    def optimize_scan_performance(self):
        """Optimize scanner performance based on current stats"""
        if self.performance_stats['avg_scan_time'] > 30:  # If scans take more than 30 seconds
            self.parallel_workers = min(8, self.parallel_workers + 1)
            self.scan_timeout = max(1, self.scan_timeout - 0.5)
            print(f"Performance optimization: Increased workers to {self.parallel_workers}, reduced timeout to {self.scan_timeout}s")
        elif self.performance_stats['avg_scan_time'] < 5:  # If scans are very fast
            self.parallel_workers = max(2, self.parallel_workers - 1)
            self.scan_timeout = min(3, self.scan_timeout + 0.5)
            print(f"Performance optimization: Decreased workers to {self.parallel_workers}, increased timeout to {self.scan_timeout}s")

