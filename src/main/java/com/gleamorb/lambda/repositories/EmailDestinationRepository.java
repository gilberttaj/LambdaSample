package com.gleamorb.lambda.repositories;

import com.gleamorb.lambda.models.EmailDestination;
import com.gleamorb.lambda.services.DatabaseConnectionManager;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Repository class for database operations related to Email Destinations
 */
public class EmailDestinationRepository {
    private static final Logger logger = Logger.getLogger(EmailDestinationRepository.class.getName());
    private final DatabaseConnectionManager connectionManager;
    
    public EmailDestinationRepository() {
        this.connectionManager = new DatabaseConnectionManager();
    }
    
    /**
     * Create a new email destination record
     */
    public boolean create(EmailDestination emailDestination) {
        String sql = "INSERT INTO email_destinations (id, user_id, display_code, department_code, chain_code, " +
                "input_method, receipt_type, processing_source_code, file_format, source_file_pattern, " +
                "destination_directory, email_title, source_file_path, destination_file_path, auto_resend) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, emailDestination.getId());
            pstmt.setString(2, emailDestination.getUserId());
            pstmt.setString(3, emailDestination.getDisplayCode());
            pstmt.setString(4, emailDestination.getDepartmentCode());
            pstmt.setString(5, emailDestination.getChainCode());
            pstmt.setString(6, emailDestination.getInputMethod());
            pstmt.setString(7, emailDestination.getReceiptType());
            pstmt.setString(8, emailDestination.getProcessingSourceCode());
            pstmt.setString(9, emailDestination.getFileFormat());
            pstmt.setString(10, emailDestination.getSourceFilePattern());
            pstmt.setString(11, emailDestination.getDestinationDirectory());
            pstmt.setString(12, emailDestination.getEmailTitle());
            pstmt.setString(13, emailDestination.getSourceFilePath());
            pstmt.setString(14, emailDestination.getDestinationFilePath());
            pstmt.setBoolean(15, emailDestination.isAutoResend());
            
            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Insert email addresses if present
                if (emailDestination.getEmailAddresses() != null && !emailDestination.getEmailAddresses().isEmpty()) {
                    insertEmailAddresses(emailDestination.getId(), emailDestination.getEmailAddresses());
                }
                
                return true;
            }
            return false;
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error creating email destination", e);
            return false;
        }
    }
    
    /**
     * Update an existing email destination record
     */
    public boolean update(EmailDestination emailDestination) {
        String sql = "UPDATE email_destinations SET display_code = ?, department_code = ?, chain_code = ?, " +
                "input_method = ?, receipt_type = ?, processing_source_code = ?, file_format = ?, " +
                "source_file_pattern = ?, destination_directory = ?, email_title = ?, source_file_path = ?, " +
                "destination_file_path = ?, auto_resend = ?, update_user = ?, update_date = CURRENT_TIMESTAMP " +
                "WHERE id = ?";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, emailDestination.getDisplayCode());
            pstmt.setString(2, emailDestination.getDepartmentCode());
            pstmt.setString(3, emailDestination.getChainCode());
            pstmt.setString(4, emailDestination.getInputMethod());
            pstmt.setString(5, emailDestination.getReceiptType());
            pstmt.setString(6, emailDestination.getProcessingSourceCode());
            pstmt.setString(7, emailDestination.getFileFormat());
            pstmt.setString(8, emailDestination.getSourceFilePattern());
            pstmt.setString(9, emailDestination.getDestinationDirectory());
            pstmt.setString(10, emailDestination.getEmailTitle());
            pstmt.setString(11, emailDestination.getSourceFilePath());
            pstmt.setString(12, emailDestination.getDestinationFilePath());
            pstmt.setBoolean(13, emailDestination.isAutoResend());
            pstmt.setString(14, emailDestination.getUpdateUser());
            pstmt.setString(15, emailDestination.getId());
            
            int affectedRows = pstmt.executeUpdate();
            
            if (affectedRows > 0) {
                // Update email addresses
                deleteEmailAddresses(emailDestination.getId());
                if (emailDestination.getEmailAddresses() != null && !emailDestination.getEmailAddresses().isEmpty()) {
                    insertEmailAddresses(emailDestination.getId(), emailDestination.getEmailAddresses());
                }
                return true;
            }
            return false;
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error updating email destination", e);
            return false;
        }
    }
    
    /**
     * Delete an email destination record
     */
    public boolean delete(String id) {
        // First delete related email addresses
        deleteEmailAddresses(id);
        
        // Then delete the main record
        String sql = "DELETE FROM email_destinations WHERE id = ?";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, id);
            
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error deleting email destination", e);
            return false;
        }
    }
    
    /**
     * Find an email destination by ID
     */
    public Optional<EmailDestination> findById(String id) {
        String sql = "SELECT * FROM email_destinations WHERE id = ?";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, id);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    EmailDestination destination = mapResultSetToEmailDestination(rs);
                    destination.setEmailAddresses(getEmailAddresses(id));
                    return Optional.of(destination);
                }
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error finding email destination by ID", e);
        }
        
        return Optional.empty();
    }
    
    /**
     * Get all email destinations
     */
    public List<EmailDestination> findAll() {
        String sql = "SELECT * FROM email_destinations";
        List<EmailDestination> destinations = new ArrayList<>();
        
        try (Connection conn = connectionManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                EmailDestination destination = mapResultSetToEmailDestination(rs);
                destination.setEmailAddresses(getEmailAddresses(destination.getId()));
                destinations.add(destination);
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error finding all email destinations", e);
        }
        
        return destinations;
    }
    
    // Helper methods
    private EmailDestination mapResultSetToEmailDestination(ResultSet rs) throws SQLException {
        EmailDestination destination = new EmailDestination();
        destination.setId(rs.getString("id"));
        destination.setUserId(rs.getString("user_id"));
        destination.setRegistrationDate(rs.getTimestamp("registration_date"));
        destination.setApprovalUser(rs.getString("approval_user"));
        destination.setApprovalDate(rs.getTimestamp("approval_date"));
        destination.setUpdateUser(rs.getString("update_user"));
        destination.setUpdateDate(rs.getTimestamp("update_date"));
        destination.setDisplayCode(rs.getString("display_code"));
        destination.setDepartmentCode(rs.getString("department_code"));
        destination.setChainCode(rs.getString("chain_code"));
        destination.setInputMethod(rs.getString("input_method"));
        destination.setReceiptType(rs.getString("receipt_type"));
        destination.setProcessingSourceCode(rs.getString("processing_source_code"));
        destination.setFileFormat(rs.getString("file_format"));
        destination.setSourceFilePattern(rs.getString("source_file_pattern"));
        destination.setDestinationDirectory(rs.getString("destination_directory"));
        destination.setEmailTitle(rs.getString("email_title"));
        destination.setSourceFilePath(rs.getString("source_file_path"));
        destination.setDestinationFilePath(rs.getString("destination_file_path"));
        destination.setAutoResend(rs.getBoolean("auto_resend"));
        return destination;
    }
    
    private void insertEmailAddresses(String destinationId, List<String> emailAddresses) {
        String sql = "INSERT INTO email_destination_addresses (destination_id, email_address) VALUES (?, ?)";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            for (String email : emailAddresses) {
                pstmt.setString(1, destinationId);
                pstmt.setString(2, email);
                pstmt.addBatch();
            }
            
            pstmt.executeBatch();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error inserting email addresses", e);
        }
    }
    
    private void deleteEmailAddresses(String destinationId) {
        String sql = "DELETE FROM email_destination_addresses WHERE destination_id = ?";
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, destinationId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error deleting email addresses", e);
        }
    }
    
    private List<String> getEmailAddresses(String destinationId) {
        String sql = "SELECT email_address FROM email_destination_addresses WHERE destination_id = ?";
        List<String> emailAddresses = new ArrayList<>();
        
        try (Connection conn = connectionManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, destinationId);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    emailAddresses.add(rs.getString("email_address"));
                }
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error getting email addresses", e);
        }
        
        return emailAddresses;
    }
}
