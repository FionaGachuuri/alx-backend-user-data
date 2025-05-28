#!/usr/bin/env python3
"""
Basic authentication module for API
"""
from api.v1.auth.auth import Auth
import base64
from typing import Optional
from typing import TypeVar


class BasicAuth(Auth):
    """Basic authentication class that inherits from Auth"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header"""
        if not authorization_header or not isinstance(
                        authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """Decodes the Base64 authorization header"""
        if not base64_authorization_header or not isinstance(
                        base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        Extracts user credentials from the decoded Base64 authorization heade
        """
        if not decoded_base64_authorization_header or not isinstance(
                        decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user, password = decoded_base64_authorization_header.split(':', 1)
        return user, password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Returns the User object based on the provided credentials
        """
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None
        from models.user import User
        try:
            user = User.search({'email': user_email})
            if not user:
                return None
            if not User.verify_password(user_pwd, user.password):
                return None
            return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns the current user based on the request
        """
        if request is None:
            return None
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        base64_auth_header = self.extract_base64_authorization_header(
            auth_header)
        if not base64_auth_header:
            return None
        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header)
        if not decoded_auth_header:
            return None
        user_email, user_pwd = self.extract_user_credentials(
            decoded_auth_header)
        if not user_email or not user_pwd:
            return None
        return self.user_object_from_credentials(user_email, user_pwd)
