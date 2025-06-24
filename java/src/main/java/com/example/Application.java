package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;

/**
 * Main Spring Boot application class.
 * This file contains various issues for testing the AI reviewer.
 */
@SpringBootApplication
@RestController
public class Application {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // Hardcoded database credentials (security issue)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password123"; // Security issue: hardcoded password
    
    // Hardcoded API key (security issue)
    private static final String API_KEY = "sk-1234567890abcdef";
    
    // Insecure password encoder (security issue)
    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4); // Too few rounds

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /**
     * Get all users - missing authentication and authorization.
     */
    @GetMapping("/api/users")
    public List<Map<String, Object>> getUsers() {
        // Missing authentication check
        String sql = "SELECT id, username, email FROM users";
        return jdbcTemplate.queryForList(sql);
    }

    /**
     * Create user - vulnerable to SQL injection and missing input validation.
     */
    @PostMapping("/api/users")
    public Map<String, String> createUser(@RequestBody Map<String, String> userData) {
        Map<String, String> response = new HashMap<>();
        
        // Missing input validation
        String username = userData.get("username");
        String email = userData.get("email");
        String password = userData.get("password");
        
        // Insecure password validation
        if (password == null || password.length() < 6) {
            response.put("error", "Password too short");
            return response;
        }
        
        try {
            // Vulnerable to SQL injection
            String sql = "INSERT INTO users (username, email, password) VALUES ('" + 
                        username + "', '" + email + "', '" + password + "')";
            jdbcTemplate.execute(sql);
            
            response.put("message", "User created successfully");
        } catch (Exception e) {
            response.put("error", "Failed to create user: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * Get user by ID - vulnerable to SQL injection.
     */
    @GetMapping("/api/users/{id}")
    public Map<String, Object> getUserById(@PathVariable String id) {
        // Vulnerable to SQL injection
        String sql = "SELECT * FROM users WHERE id = " + id;
        List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);
        
        if (!users.isEmpty()) {
            return users.get(0);
        } else {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "User not found");
            return error;
        }
    }

    /**
     * Login endpoint - insecure implementation.
     */
    @PostMapping("/api/login")
    public Map<String, String> login(@RequestBody Map<String, String> credentials) {
        Map<String, String> response = new HashMap<>();
        
        String username = credentials.get("username");
        String password = credentials.get("password");
        
        try {
            // Plain text password comparison (security issue)
            String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
            List<Map<String, Object>> users = jdbcTemplate.queryForList(sql, username, password);
            
            if (!users.isEmpty()) {
                response.put("message", "Login successful");
            } else {
                response.put("error", "Invalid credentials");
            }
        } catch (Exception e) {
            response.put("error", "Login failed: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * File upload endpoint - missing file validation.
     */
    @PostMapping("/api/upload")
    public Map<String, String> uploadFile(@RequestParam("file") String fileContent) {
        Map<String, String> response = new HashMap<>();
        
        // Missing file type validation
        // Missing file size validation
        // Missing virus scanning
        
        try {
            // Insecure file writing (security issue)
            java.nio.file.Files.write(
                java.nio.file.Paths.get("/tmp/uploaded_file.txt"),
                fileContent.getBytes()
            );
            response.put("message", "File uploaded successfully");
        } catch (Exception e) {
            response.put("error", "Upload failed: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * Execute command endpoint - vulnerable to command injection.
     */
    @PostMapping("/api/execute")
    public Map<String, String> executeCommand(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        
        String command = request.get("command");
        
        // Vulnerable to command injection (security issue)
        try {
            Process process = Runtime.getRuntime().exec(command);
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            response.put("output", output.toString());
        } catch (Exception e) {
            response.put("error", "Command execution failed: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * Get sensitive data - missing access control.
     */
    @GetMapping("/api/admin/data")
    public Map<String, Object> getAdminData() {
        // Missing admin role check
        Map<String, Object> data = new HashMap<>();
        data.put("users", jdbcTemplate.queryForList("SELECT * FROM users"));
        data.put("config", getSystemConfig());
        return data;
    }

    /**
     * Get system configuration - hardcoded sensitive data.
     */
    private Map<String, String> getSystemConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("database_url", DB_URL);
        config.put("database_user", DB_USER);
        config.put("api_key", API_KEY);
        config.put("secret_token", "super-secret-token-12345");
        return config;
    }

    /**
     * Process payment - missing validation and error handling.
     */
    @PostMapping("/api/payment")
    public Map<String, String> processPayment(@RequestBody Map<String, Object> paymentData) {
        Map<String, String> response = new HashMap<>();
        
        // Missing payment validation
        Double amount = (Double) paymentData.get("amount");
        String cardNumber = (String) paymentData.get("cardNumber");
        
        // Missing credit card validation
        // Missing amount validation
        // Missing currency validation
        
        try {
            // Simulate payment processing
            if (amount > 0) {
                response.put("message", "Payment processed successfully");
                response.put("transaction_id", generateTransactionId());
            } else {
                response.put("error", "Invalid amount");
            }
        } catch (Exception e) {
            response.put("error", "Payment failed: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * Generate transaction ID - insecure implementation.
     */
    private String generateTransactionId() {
        // Security issue: using predictable ID generation
        return "TXN" + System.currentTimeMillis();
    }
} 