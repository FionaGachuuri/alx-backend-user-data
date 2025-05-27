#!/usr/bin/env python3
"""
Auth module for managing API authentication
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Template for all authentication systems"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determines if authentication is required for a given path"""
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('/') and path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Returns the authorization header from the request"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user"""
        return None
