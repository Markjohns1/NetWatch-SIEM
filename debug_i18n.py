#!/usr/bin/env python3
"""
Debug script to test i18n functionality
"""
from i18n import I18nManager
from flask import Flask

# Create a test Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret'

# Initialize i18n
i18n = I18nManager()
i18n.init_app(app)

# Test with app context
with app.app_context():
    # Debug app paths
    print(f"App root_path: {app.root_path}")
    print(f"App instance_path: {app.instance_path}")
    
    # Test gettext function
    print("\nTesting gettext function:")
    print(f"network_devices: {i18n.gettext('network_devices')}")
    print(f"active_devices: {i18n.gettext('active_devices')}")
    print(f"critical_alerts: {i18n.gettext('critical_alerts')}")
    print(f"trusted_devices: {i18n.gettext('trusted_devices')}")
    
    # Test current language
    print(f"\nCurrent language: {i18n.get_current_language()}")
    
    # Test translations loading
    print(f"\nLoaded translations: {list(i18n.translations.keys())}")
    
    # Test specific translation
    if 'en' in i18n.translations:
        print(f"English translations loaded: {len(i18n.translations['en'])} keys")
        print(f"network_devices in EN: {i18n.translations['en'].get('network_devices', 'NOT FOUND')}")
    else:
        print("English translations not loaded!")
