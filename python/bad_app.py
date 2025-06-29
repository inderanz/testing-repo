import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SECURITY ISSUE: Hardcoded credentials
DB_USER = "admin"
DB_PASSWORD = "supersecret"
API_KEY = "sk_test_1234567890abcdef"

@app.route('/run', methods=['POST'])
def run_command():
    # SECURITY ISSUE: Command injection
    cmd = request.form.get('cmd')
    os.system(cmd)
    return "Command executed"

@app.route('/query', methods=['POST'])
def query():
    # SECURITY ISSUE: SQL injection
    q = request.form.get('q')
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    cur.execute(q)
    return str(cur.fetchall())

@app.route('/login', methods=['POST'])
def login():
    # SECURITY ISSUE: No input validation
    username = request.form.get('username')
    password = request.form.get('password')
    if username == DB_USER and password == DB_PASSWORD:
        return "Welcome!"
    return "Invalid credentials"

if __name__ == '__main__':
    # SECURITY ISSUE: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
