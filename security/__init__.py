"""
Security package for NetWatch SIEM
Provides authentication, authorization, and security utilities
"""

from .auth import SecurityManager, require_auth, require_admin, rate_limit, validate_input, sanitize_input
from .rbac import has_permission, require_permission, require_any_permission, get_user_role, is_admin, ROLE_PERMISSIONS

__all__ = [
    'SecurityManager',
    'require_auth', 
    'require_admin',
    'rate_limit',
    'validate_input',
    'sanitize_input',
    'has_permission',
    'require_permission',
    'require_any_permission',
    'get_user_role',
    'is_admin',
    'ROLE_PERMISSIONS'
]
