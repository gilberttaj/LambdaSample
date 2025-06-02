package com.gleamorb.lambda.services;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Service for managing database connections to RDS
 */
public class DatabaseConnectionManager {
    private static final Logger logger = Logger.getLogger(DatabaseConnectionManager.class.getName());
    
    // Default local development environment
    private static final String LOCAL_DB_URL = "jdbc:postgresql://host.docker.internal:5432/gleamorb_db";
    private static final String LOCAL_DB_USER = "postgres";
    private static final String LOCAL_DB_PASSWORD = "password";
    
    // Connection parameters
    private String dbUrl;
    private String dbUser;
    private String dbPassword;
    
    public DatabaseConnectionManager() {
        // Initialize with environment variables or fall back to local defaults
        this.dbUrl = System.getenv("DB_URL");
        this.dbUser = System.getenv("DB_USER");
        this.dbPassword = System.getenv("DB_PASSWORD");
        
        // Fall back to local defaults if environment variables are not set
        if (dbUrl == null || dbUrl.isEmpty()) {
            this.dbUrl = LOCAL_DB_URL;
        }
        
        if (dbUser == null || dbUser.isEmpty()) {
            this.dbUser = LOCAL_DB_USER;
        }
        
        if (dbPassword == null || dbPassword.isEmpty()) {
            this.dbPassword = LOCAL_DB_PASSWORD;
        }
    }
    
    /**
     * Get a database connection
     * 
     * @return Connection to the database
     * @throws SQLException if a database access error occurs
     */
    public Connection getConnection() throws SQLException {
        try {
            // Load the JDBC driver
            Class.forName("org.postgresql.Driver");
            
            // Log connection attempt
            logger.info("Attempting to connect to database with URL: " + dbUrl);
            
            // Create and return the connection
            return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
        } catch (ClassNotFoundException e) {
            logger.log(Level.SEVERE, "PostgreSQL JDBC Driver not found", e);
            throw new SQLException("PostgreSQL JDBC Driver not found", e);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Failed to connect to database", e);
            throw e;
        }
    }
}
