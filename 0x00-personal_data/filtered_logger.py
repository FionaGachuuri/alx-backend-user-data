#!/usr/bin/env python3
"""
Module that provides a function to filter sensitive data
from log messages using regular expressions.
"""
import re
from typing import List
import logging


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


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    that replaces sensitive data in log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Class accepts  a list of strings as fields constructor
        argument. Implement the format method to filter values
        in incoming log records using filter_datum.
        Args:
            fields: List of fields to obfuscate.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """"
        Formats the log record, filtering sensitive data.

        Args:
            record: The log record to format.

        Returns:
            The formatted log message with sensitive data filtered.
        """
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION,
                            message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Returns a logger object configured with the RedactingFormatter.

    Returns:
        A logger object with the RedactingFormatter.
    """
    filter_logger = logging.getLogger("user_data")
    if filter_logger.hasHandlers():
        filter_logger.handlers.clear()
    else:
        filter_logger.propagate = False
    filter_logger.propagate = False
    filter_logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=["email", "ssn", "password"]))
    filter_logger.addHandler(handler)
    return filter_logger
PII_FIELDS = ('name', 'email', 'address', 'ssn', 'password')
