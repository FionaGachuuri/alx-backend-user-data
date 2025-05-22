#!/usr/bin/env python3
"""
Module that provides a function to filter sensitive data
from log messages using regular expressions.
"""
import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscates the values of specified fields within a log message.

    Args:
        fields: List of fields to obfuscate.
        redaction: The string to replace sensitive values with.
        message: The original log message.
        separator: The character separating the fields in the message.

    Returns:
        The log message with specified fields obfuscated.
    """
    return re.sub(rf'({"|".join(fields)})=.*?{separator}',
                  lambda m: f"{m.group(1)}={redaction}{separator}", message)
