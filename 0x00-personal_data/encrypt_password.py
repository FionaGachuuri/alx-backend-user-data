#!/usr/bin/env python3
"""
This module contains the hash_password function that
uses bcrypt to encrypt the password it receives as an argument.
It also contains the is_valid function that checks if the
password matches the hashed password.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.
    The password is converted to bytes and salted before hashing.
    The bcrypt.gensalt() function generates a salt for the password.
    The bcrypt.hashpw() function hashes the password with the salt.
    The hashed password is returned as bytes.
    Args:
        password (str): string type password

    Returns:
        bytes: salted, hashed password
    """
    return bcrypt.hashpw(bytes(password, "utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks if the provided password matches the hashed password.
    The password is converted to bytes before checking.
    Args:
        hashed_password (bytes): salted, hashed password
        password (str): string type password

    Returns:
        bool: True if the password is valid, False otherwise
    """
    return bcrypt.checkpw(bytes(password, "utf-8"), hashed_password)
