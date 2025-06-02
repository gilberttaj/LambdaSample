package com.gleamorb.lambda.models;

import java.util.Date;
import java.util.List;

/**
 * Model class representing an email destination record
 * Based on the "メール宛先マスター" (Email Destination Master) screen from requirements
 */
public class EmailDestination {
    private String id;
    private String userId;
    private Date registrationDate;
    private String approvalUser;
    private Date approvalDate;
    private String updateUser;
    private Date updateDate;
    
    private String displayCode;
    private String departmentCode;
    private String chainCode;
    private String inputMethod;
    private String receiptType;
    
    private String processingSourceCode;
    private String fileFormat;
    private String sourceFilePattern;
    private String destinationDirectory;
    private String emailTitle;
    
    private String sourceFilePath;
    private String destinationFilePath;
    
    private List<String> emailAddresses;
    
    private boolean autoResend;

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Date getRegistrationDate() {
        return registrationDate;
    }

    public void setRegistrationDate(Date registrationDate) {
        this.registrationDate = registrationDate;
    }

    public String getApprovalUser() {
        return approvalUser;
    }

    public void setApprovalUser(String approvalUser) {
        this.approvalUser = approvalUser;
    }

    public Date getApprovalDate() {
        return approvalDate;
    }

    public void setApprovalDate(Date approvalDate) {
        this.approvalDate = approvalDate;
    }

    public String getUpdateUser() {
        return updateUser;
    }

    public void setUpdateUser(String updateUser) {
        this.updateUser = updateUser;
    }

    public Date getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(Date updateDate) {
        this.updateDate = updateDate;
    }

    public String getDisplayCode() {
        return displayCode;
    }

    public void setDisplayCode(String displayCode) {
        this.displayCode = displayCode;
    }

    public String getDepartmentCode() {
        return departmentCode;
    }

    public void setDepartmentCode(String departmentCode) {
        this.departmentCode = departmentCode;
    }

    public String getChainCode() {
        return chainCode;
    }

    public void setChainCode(String chainCode) {
        this.chainCode = chainCode;
    }

    public String getInputMethod() {
        return inputMethod;
    }

    public void setInputMethod(String inputMethod) {
        this.inputMethod = inputMethod;
    }

    public String getReceiptType() {
        return receiptType;
    }

    public void setReceiptType(String receiptType) {
        this.receiptType = receiptType;
    }

    public String getProcessingSourceCode() {
        return processingSourceCode;
    }

    public void setProcessingSourceCode(String processingSourceCode) {
        this.processingSourceCode = processingSourceCode;
    }

    public String getFileFormat() {
        return fileFormat;
    }

    public void setFileFormat(String fileFormat) {
        this.fileFormat = fileFormat;
    }

    public String getSourceFilePattern() {
        return sourceFilePattern;
    }

    public void setSourceFilePattern(String sourceFilePattern) {
        this.sourceFilePattern = sourceFilePattern;
    }

    public String getDestinationDirectory() {
        return destinationDirectory;
    }

    public void setDestinationDirectory(String destinationDirectory) {
        this.destinationDirectory = destinationDirectory;
    }

    public String getEmailTitle() {
        return emailTitle;
    }

    public void setEmailTitle(String emailTitle) {
        this.emailTitle = emailTitle;
    }

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }

    public String getDestinationFilePath() {
        return destinationFilePath;
    }

    public void setDestinationFilePath(String destinationFilePath) {
        this.destinationFilePath = destinationFilePath;
    }

    public List<String> getEmailAddresses() {
        return emailAddresses;
    }

    public void setEmailAddresses(List<String> emailAddresses) {
        this.emailAddresses = emailAddresses;
    }

    public boolean isAutoResend() {
        return autoResend;
    }

    public void setAutoResend(boolean autoResend) {
        this.autoResend = autoResend;
    }
}
