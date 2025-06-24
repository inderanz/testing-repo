# Testing Repository

This repository contains sample code in multiple languages (Terraform, Python, Java) with various intentional issues for testing AI-powered code review tools.

## Project Structure

```
testing-repo/
├── terraform/
│   ├── main.tf          # Main Terraform configuration
│   └── variables.tf     # Terraform variables
├── python/
│   ├── app.py           # Flask web application
│   └── utils.py         # Utility functions
├── java/
│   ├── pom.xml          # Maven configuration
│   └── src/main/java/com/example/
│       ├── Application.java  # Spring Boot application
│       └── UserService.java  # User service class
└── README.md            # This file
```

## Languages and Technologies

### Terraform
- AWS infrastructure provisioning
- Security groups and IAM roles
- S3 buckets and EC2 instances
- Various security and compliance issues

### Python
- Flask web application
- SQLite database operations
- Utility functions
- Security vulnerabilities and best practice violations

### Java
- Spring Boot application
- RESTful API endpoints
- Database operations with JDBC
- Security and validation issues

## Issues Included for Testing

### Security Issues
- SQL injection vulnerabilities
- Command injection vulnerabilities
- Hardcoded credentials and secrets
- Insecure password handling
- Missing input validation
- Path traversal vulnerabilities
- Overly permissive access controls

### Compliance Issues
- Missing variable validations
- Hardcoded values
- Missing documentation
- Incomplete error handling

### Best Practice Issues
- Missing type hints
- Incomplete docstrings
- Poor error handling
- Missing logging
- Inefficient algorithms

### Dependency Issues
- Outdated dependencies
- Missing dependency management
- Security vulnerabilities in dependencies

### Test Coverage Issues
- Missing unit tests
- Incomplete test coverage
- Missing integration tests

### Documentation Issues
- Missing API documentation
- Incomplete README
- Missing inline comments

## Usage

This repository is designed for testing AI-powered code review tools. The code contains intentional issues that should be identified by automated review systems.

## Contributing

This is a test repository. Please do not submit actual production code to this repository.

## License

This project is for testing purposes only.