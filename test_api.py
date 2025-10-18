#!/usr/bin/env python3
"""
Test script to verify NetWatch SIEM API functionality
"""
import requests
import json
from database.models import Database

def test_database():
    """Test database functionality"""
    print("Testing database...")
    db = Database()
    
    # Test dashboard stats
    stats = db.get_dashboard_stats()
    print(f"Dashboard stats: {stats}")
    
    # Test devices
    devices = db.get_all_devices()
    print(f"Total devices: {len(devices)}")
    
    # Test alerts
    alerts = db.get_recent_alerts(5)
    print(f"Recent alerts: {len(alerts)}")
    
    return True

def test_api_with_auth():
    """Test API with authentication"""
    print("\nTesting API with authentication...")
    
    # Create a session
    session = requests.Session()
    
    # Login
    login_data = {
        'username': 'Mark',
        'password': 'lizzyjohn'
    }
    
    try:
        # Get login page first
        response = session.get('http://localhost:5000/login')
        print(f"Login page status: {response.status_code}")
        
        # Login
        response = session.post('http://localhost:5000/login', data=login_data)
        print(f"Login response status: {response.status_code}")
        
        if response.status_code == 302:  # Redirect after successful login
            # Test dashboard stats API
            response = session.get('http://localhost:5000/api/dashboard/stats')
            print(f"Dashboard stats API status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Dashboard stats data: {json.dumps(data, indent=2)}")
                return True
            else:
                print(f"Dashboard stats API error: {response.text}")
        else:
            print(f"Login failed: {response.text}")
            
    except Exception as e:
        print(f"API test error: {e}")
    
    return False

if __name__ == "__main__":
    print("NetWatch SIEM API Test")
    print("=" * 50)
    
    # Test database
    db_ok = test_database()
    
    # Test API
    api_ok = test_api_with_auth()
    
    print("\n" + "=" * 50)
    print(f"Database test: {'PASS' if db_ok else 'FAIL'}")
    print(f"API test: {'PASS' if api_ok else 'FAIL'}")
