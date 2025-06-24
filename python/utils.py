#!/usr/bin/env python3
"""
Utility functions for the application.
This file contains various issues for testing the AI reviewer.
"""

import os
import subprocess
import hashlib
import base64
import json
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

# Global variable without proper scoping (best practice issue)
API_KEY = "sk-1234567890abcdef"  # Security issue: hardcoded API key

def execute_command(command: str) -> str:
    """Execute shell command - vulnerable to command injection."""
    # Security issue: vulnerable to command injection
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def hash_password(password: str) -> str:
    """Hash password using MD5 - insecure algorithm."""
    # Security issue: using MD5 which is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def encode_data(data: str) -> str:
    """Encode data using base64."""
    return base64.b64encode(data.encode()).decode()

def decode_data(encoded_data: str) -> str:
    """Decode base64 data - missing error handling."""
    # Missing error handling for invalid base64
    return base64.b64decode(encoded_data.encode()).decode()

def read_file(file_path: str) -> str:
    """Read file content - missing path validation."""
    # Security issue: missing path validation (path traversal vulnerability)
    with open(file_path, 'r') as file:
        return file.read()

def write_file(file_path: str, content: str) -> None:
    """Write content to file - missing path validation."""
    # Security issue: missing path validation
    with open(file_path, 'w') as file:
        file.write(content)

def validate_email(email: str) -> bool:
    """Validate email format - incomplete validation."""
    # Incomplete email validation
    return '@' in email and '.' in email

def validate_phone(phone: str) -> bool:
    """Validate phone number - missing validation."""
    # Missing phone number validation
    return len(phone) >= 10

def process_user_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process user data - missing input validation."""
    # Missing input validation
    processed_data = {
        'id': user_data.get('id'),
        'name': user_data.get('name', '').strip(),
        'email': user_data.get('email', '').lower(),
        'age': user_data.get('age', 0),  # Missing type validation
        'active': user_data.get('active', True)
    }
    return processed_data

def calculate_discount(price: float, discount_percent: float) -> float:
    """Calculate discount - missing input validation."""
    # Missing input validation for negative values
    return price * (1 - discount_percent / 100)

def format_currency(amount: float) -> str:
    """Format currency - missing locale handling."""
    # Missing locale handling
    return f"${amount:.2f}"

def log_sensitive_data(data: str) -> None:
    """Log sensitive data - security issue."""
    # Security issue: logging sensitive data
    logger.info(f"Sensitive data: {data}")

def create_backup(file_path: str) -> str:
    """Create backup file - missing error handling."""
    # Missing error handling
    backup_path = f"{file_path}.backup"
    with open(file_path, 'r') as source:
        with open(backup_path, 'w') as backup:
            backup.write(source.read())
    return backup_path

def delete_file(file_path: str) -> bool:
    """Delete file - missing validation."""
    # Missing file existence check and validation
    try:
        os.remove(file_path)
        return True
    except OSError:
        return False

def get_environment_variable(key: str, default: str = "") -> str:
    """Get environment variable - missing validation."""
    # Missing validation for required environment variables
    return os.getenv(key, default)

def parse_json(json_string: str) -> Dict[str, Any]:
    """Parse JSON string - missing error handling."""
    # Missing error handling for invalid JSON
    return json.loads(json_string)

def generate_random_string(length: int = 10) -> str:
    """Generate random string - insecure implementation."""
    import random
    import string
    # Security issue: using random instead of secrets for cryptographic purposes
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Missing type hints for some functions
# Missing docstrings for some functions
# Missing error handling in many functions
# Missing input validation in most functions 