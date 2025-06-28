# Simple test file with obvious security issues

def bad_function():
    password = "secret123"  # SECURITY ISSUE: Hardcoded password
    print("Hello world")
    return password

def another_bad_function():
    # SECURITY ISSUE: No input validation
    user_input = input("Enter your data: ")
    eval(user_input)  # SECURITY ISSUE: Dangerous eval usage
    return user_input

if __name__ == "__main__":
    bad_function()
    another_bad_function() 