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
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
                else:
                    if not excluded_path.startswith('/'):
                        excluded_path += '/'
            if path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Returns the authorization header from the request"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user"""
        return None
