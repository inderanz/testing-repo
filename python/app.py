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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-12345"  # Security issue: hardcoded secret

# Database connection without proper error handling
def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect('database.db')  # Missing error handling
    conn.row_factory = sqlite3.Row
    return conn

# SQL injection vulnerable function (security issue)
def get_user_by_id(user_id):
    """Get user by ID - vulnerable to SQL injection."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

# Insecure password validation (security issue)
def validate_password(password):
    """Validate password - insecure implementation."""
    if len(password) >= 6:  # Too short minimum length
        return True
    return False

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users - missing authentication."""
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
    """Create a new user - missing input validation."""
    data = request.get_json()
    
    # Missing input validation
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Insecure password validation
    if not validate_password(password):
        return jsonify({"error": "Invalid password"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Missing password hashing
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, password)  # Security issue: plain text password
        )
        conn.commit()
        conn.close()
        
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get user by ID - vulnerable to SQL injection."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404

@app.route('/api/login', methods=['POST'])
def login():
    """User login - insecure implementation."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['password'] == password:  # Security issue: plain text comparison
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Missing error handlers
# Missing rate limiting
# Missing CORS configuration
# Missing request size limits

if __name__ == '__main__':
    # Development server - not suitable for production
    app.run(debug=True, host='0.0.0.0', port=5000)  # Security issue: debug mode in production # Small PR test
# Tiny PR test
