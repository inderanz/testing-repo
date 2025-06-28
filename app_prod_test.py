# Production-grade test file for LLM review
import os
import json
import requests

def insecure_login():
    # SECURITY ISSUE: Hardcoded credentials
    username = 'admin'
    password = 'password123'
    
    # SECURITY ISSUE: No input validation
    user_input = input('Enter your username: ')
    if user_input == username:
        print('Welcome admin!')
    else:
        print('Access denied!')
    
    # SECURITY ISSUE: Dangerous eval usage
    data = input('Enter data: ')
    eval(data)
    
    # SECURITY ISSUE: Unencrypted HTTP request
    r = requests.get('http://example.com/api', params={'user': user_input})
    print(r.text)
    
    # CODE QUALITY: Unused variable
    unused = 42
    
    # CODE QUALITY: No error handling
    f = open('sensitive.txt', 'r')
    print(f.read())
    f.close()

# Bad practice: global variable
config = {}

if __name__ == '__main__':
    insecure_login() 