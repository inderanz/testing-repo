#!/usr/bin/env python3
"""
Main Flask application for the web service.
This file contains various issues for testing the AI reviewer.
"""

import os
import json
import sqlite3
from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'hardcoded-secret-key-12345')  # Still has fallback issue

# Database connection with improved error handling
def get_db_connection():
    """Get database connection with error handling."""
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

# Improved function with parameterized query (still has some issues)
def get_user_by_id(user_id):
    """Get user by ID - improved with parameterized query."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Fixed SQL injection vulnerability
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

# Improved password validation (still has issues)
def validate_password(password):
    """Validate password - improved but still insecure."""
    if password is None:
        return False
    if len(password) < 8:  # Still too short
        return False
    # Missing complexity requirements
    return True

# Simple authentication decorator (incomplete)
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Missing proper authentication logic
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
@require_auth  # Added authentication requirement
def get_users():
    """Get all users - now requires authentication."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
        conn.close()
        return jsonify([dict(user) for user in users])
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user - improved with input validation."""
    data = request.get_json()
    
    # Improved input validation
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Improved password validation
    if not validate_password(password):
        return jsonify({"error": "Invalid password"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Improved password hashing (still using plain text in some cases)
        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)  # Fixed: now using hashed password
        )
        conn.commit()
        conn.close()
        
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    """Get user by ID - now uses improved function."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404

@app.route('/api/login', methods=['POST'])
def login():
    """User login - improved implementation."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):  # Fixed: now using proper password checking
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Added error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Still missing:
# - Rate limiting
# - CORS configuration
# - Request size limits
# - Proper session management
# - CSRF protection

if __name__ == '__main__':
    # Development server - not suitable for production
    app.run(debug=False, host='0.0.0.0', port=5000)  # Fixed: disabled debug mode 