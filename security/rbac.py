"""
Role-Based Access Control (RBAC) for NetWatch SIEM
Defines permissions for each role and checks access
"""

from functools import wraps
from flask import session, jsonify, redirect, url_for, flash

# Define role permissions - SIMPLIFIED: only admin and viewer
ROLE_PERMISSIONS = {
    'admin': {
        'all': True,  # Admins have all permissions
        'view_devices': True,
        'manage_devices': True,
        'view_alerts': True,
        'manage_alerts': True,
        'view_logs': True,
        'manage_logs': True,
        'view_analytics': True,
        'manage_rules': True,
        'manage_users': True,
        'manage_config': True,
        'scan_network': True
    },
    'viewer': {
        'view_devices': True,
        'view_alerts': True,
        'view_logs': True,
        'view_analytics': True
    }
}

def has_permission(permission):
    """Check if current user has a specific permission"""
    if 'logged_in' not in session:
        return False
    
    role = session.get('role', 'viewer')
    
    # Admin has all permissions
    if role == 'admin':
        return True
    
    # Check role permissions
    role_perms = ROLE_PERMISSIONS.get(role, {})
    return role_perms.get(permission, False) or role_perms.get('all', False)

def require_permission(permission, redirect_on_fail=True):
    """Decorator to require a specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                if redirect_on_fail:
                    flash('Insufficient permissions', 'error')
                    return redirect(url_for('index'))
                return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_any_permission(*permissions):
    """Require at least one of the given permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                flash('Please log in', 'error')
                return redirect(url_for('login'))
            
            if any(has_permission(perm) for perm in permissions):
                return f(*args, **kwargs)
            
            flash('Insufficient permissions', 'error')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

def get_user_role():
    """Get current user's role"""
    return session.get('role', 'viewer')

def is_admin():
    """Check if current user is admin"""
    return session.get('is_admin', False) or session.get('role') == 'admin'

