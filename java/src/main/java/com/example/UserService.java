package com.example;

import org.springframework.stereotype.Service;
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
import java.util.Optional;

/**
 * User service class with business logic.
 * This file contains various issues for testing the AI reviewer.
 */
@Service
public class UserService {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // Hardcoded salt (security issue)
    private static final String SALT = "static-salt-12345";
    
    // Insecure password encoder
    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);
    
    // Hardcoded admin credentials (security issue)
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin123";

    /**
     * Create a new user - missing validation and security issues.
     */
    public boolean createUser(String username, String email, String password) {
        // Missing input validation
        if (username == null || username.isEmpty()) {
            return false;
        }
        
        // Insecure password validation
        if (password == null || password.length() < 6) {
            return false;
        }
        
        try {
            // Insecure password hashing
            String hashedPassword = hashPasswordInsecure(password);
            
            // Vulnerable to SQL injection
            String sql = "INSERT INTO users (username, email, password) VALUES ('" + 
                        username + "', '" + email + "', '" + hashedPassword + "')";
            jdbcTemplate.execute(sql);
            
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Get user by ID - vulnerable to SQL injection.
     */
    public Optional<Map<String, Object>> getUserById(String id) {
        try {
            // Vulnerable to SQL injection
            String sql = "SELECT * FROM users WHERE id = " + id;
            List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);
            
            if (!users.isEmpty()) {
                return Optional.of(users.get(0));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return Optional.empty();
    }

    /**
     * Authenticate user - insecure implementation.
     */
    public boolean authenticateUser(String username, String password) {
        try {
            // Plain text password comparison (security issue)
            String sql = "SELECT password FROM users WHERE username = ?";
            String storedPassword = jdbcTemplate.queryForObject(sql, String.class, username);
            
            if (storedPassword != null) {
                // Insecure password comparison
                return storedPassword.equals(password);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return false;
    }

    /**
     * Update user - missing validation and security issues.
     */
    public boolean updateUser(String id, Map<String, String> userData) {
        try {
            // Missing input validation
            String username = userData.get("username");
            String email = userData.get("email");
            
            // Vulnerable to SQL injection
            String sql = "UPDATE users SET username = '" + username + 
                        "', email = '" + email + "' WHERE id = " + id;
            jdbcTemplate.execute(sql);
            
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Delete user - missing authorization check.
     */
    public boolean deleteUser(String id) {
        try {
            // Missing authorization check
            String sql = "DELETE FROM users WHERE id = " + id;
            jdbcTemplate.execute(sql);
            
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Get all users - missing pagination and filtering.
     */
    public List<Map<String, Object>> getAllUsers() {
        try {
            // Missing pagination
            // Missing filtering
            // Missing sorting
            String sql = "SELECT * FROM users";
            return jdbcTemplate.queryForList(sql);
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    /**
     * Search users - vulnerable to SQL injection.
     */
    public List<Map<String, Object>> searchUsers(String searchTerm) {
        try {
            // Vulnerable to SQL injection
            String sql = "SELECT * FROM users WHERE username LIKE '%" + searchTerm + "%'";
            return jdbcTemplate.queryForList(sql);
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    /**
     * Change password - insecure implementation.
     */
    public boolean changePassword(String userId, String oldPassword, String newPassword) {
        try {
            // Get current password
            String sql = "SELECT password FROM users WHERE id = " + userId;
            String currentPassword = jdbcTemplate.queryForObject(sql, String.class);
            
            // Insecure password comparison
            if (currentPassword.equals(oldPassword)) {
                // Insecure password hashing
                String hashedNewPassword = hashPasswordInsecure(newPassword);
                
                // Update password
                String updateSql = "UPDATE users SET password = '" + hashedNewPassword + 
                                 "' WHERE id = " + userId;
                jdbcTemplate.execute(updateSql);
                
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return false;
    }

    /**
     * Reset password - insecure implementation.
     */
    public String resetPassword(String email) {
        try {
            // Generate insecure password
            String newPassword = generateInsecurePassword();
            
            // Insecure password hashing
            String hashedPassword = hashPasswordInsecure(newPassword);
            
            // Update password
            String sql = "UPDATE users SET password = '" + hashedPassword + 
                        "' WHERE email = '" + email + "'";
            jdbcTemplate.execute(sql);
            
            return newPassword;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Validate email - incomplete validation.
     */
    public boolean isValidEmail(String email) {
        // Incomplete email validation
        return email != null && email.contains("@") && email.contains(".");
    }

    /**
     * Validate username - missing validation rules.
     */
    public boolean isValidUsername(String username) {
        // Missing validation rules
        return username != null && username.length() >= 3;
    }

    /**
     * Insecure password hashing method.
     */
    private String hashPasswordInsecure(String password) {
        // Security issue: using MD5 with static salt
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            String saltedPassword = password + SALT;
            byte[] hash = md.digest(saltedPassword.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return password; // Fallback to plain text (security issue)
        }
    }

    /**
     * Generate insecure password.
     */
    private String generateInsecurePassword() {
        // Security issue: using predictable password generation
        return "password" + System.currentTimeMillis() % 1000;
    }

    /**
     * Log user activity - security issue.
     */
    public void logUserActivity(String userId, String action) {
        // Security issue: logging sensitive user activity
        System.out.println("User " + userId + " performed action: " + action);
    }

    /**
     * Get user permissions - missing implementation.
     */
    public List<String> getUserPermissions(String userId) {
        // Missing implementation
        return new ArrayList<>();
    }

    /**
     * Check if user is admin - hardcoded check.
     */
    public boolean isAdmin(String username) {
        // Security issue: hardcoded admin check
        return ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals("admin123");
    }
} 