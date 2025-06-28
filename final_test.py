# Final test file with multiple security issues

import os
import subprocess

def insecure_function():
    # SECURITY ISSUE: Hardcoded password
    password = "admin123"
    
    # SECURITY ISSUE: Command injection vulnerability
    user_input = input("Enter command: ")
    os.system(user_input)  # DANGEROUS: Command injection
    
    # SECURITY ISSUE: Dangerous eval usage
    code = input("Enter code to execute: ")
    eval(code)  # DANGEROUS: Code injection
    
    return password

def another_insecure_function():
    # SECURITY ISSUE: No input validation
    filename = input("Enter filename: ")
    
    # SECURITY ISSUE: Path traversal vulnerability
    with open(filename, 'r') as f:  # DANGEROUS: Path traversal
        content = f.read()
    
    # SECURITY ISSUE: SQL injection (simulated)
    query = f"SELECT * FROM users WHERE id = {input('Enter user ID: ')}"  # DANGEROUS: SQL injection
    
    return content

if __name__ == "__main__":
    insecure_function()
    another_insecure_function() 