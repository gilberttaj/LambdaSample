-- PostgreSQL schema for GleamOrb Email Destination Management

-- Create email_destinations table
CREATE TABLE IF NOT EXISTS email_destinations (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approval_user VARCHAR(36),
    approval_date TIMESTAMP,
    update_user VARCHAR(36),
    update_date TIMESTAMP,
    display_code VARCHAR(50) NOT NULL,
    department_code VARCHAR(50) NOT NULL,
    chain_code VARCHAR(50) NOT NULL,
    input_method VARCHAR(50) NOT NULL,
    receipt_type VARCHAR(50) NOT NULL,
    processing_source_code VARCHAR(50) NOT NULL,
    file_format VARCHAR(50) NOT NULL,
    source_file_pattern VARCHAR(255),
    destination_directory VARCHAR(255),
    email_title VARCHAR(255),
    source_file_path VARCHAR(255),
    destination_file_path VARCHAR(255),
    auto_resend BOOLEAN DEFAULT FALSE
);

-- Create email_destination_addresses table for storing multiple email addresses per destination
CREATE TABLE IF NOT EXISTS email_destination_addresses (
    id SERIAL PRIMARY KEY,
    destination_id VARCHAR(36) NOT NULL,
    email_address VARCHAR(255) NOT NULL,
    FOREIGN KEY (destination_id) REFERENCES email_destinations(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_email_destinations_user_id ON email_destinations(user_id);
CREATE INDEX IF NOT EXISTS idx_email_destination_addresses_destination_id ON email_destination_addresses(destination_id);

-- Sample data for testing (uncomment to use)
/*
INSERT INTO email_destinations (
    id, user_id, display_code, department_code, chain_code, 
    input_method, receipt_type, processing_source_code, file_format, 
    source_file_pattern, destination_directory, email_title, 
    source_file_path, destination_file_path, auto_resend
) VALUES (
    'e1b5774e-c1f0-4e0f-9f1d-9e35f33f5e8f', 'test-user', 'TEST-DEST', 'DEPT1', 'CHAIN1',
    'MANUAL', 'EMAIL', 'SRC1', 'CSV',
    '*.csv', '/destination', 'Test Email',
    '/source', '/destination', false
);

INSERT INTO email_destination_addresses (destination_id, email_address)
VALUES 
    ('e1b5774e-c1f0-4e0f-9f1d-9e35f33f5e8f', 'test1@example.com'),
    ('e1b5774e-c1f0-4e0f-9f1d-9e35f33f5e8f', 'test2@example.com');
*/
