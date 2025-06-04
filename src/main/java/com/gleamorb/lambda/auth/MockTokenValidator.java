package com.gleamorb.lambda.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Validates mock JWT tokens for local testing
 */
public class MockTokenValidator {
    private final String issuer;
    private final String audience;
    
    /**
     * Constructor for the mock token validator
     * 
     * @param region The AWS region to use in the mock issuer
     * @param userPoolId The Cognito User Pool ID to use in the mock issuer
     * @param appClientId The App Client ID to use as the audience
     */
    public MockTokenValidator(String region, String userPoolId, String appClientId) {
        // Set the issuer and audience to match what the mock token generator uses
        this.issuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
        this.audience = appClientId;
    }
    
    /**
     * Validates a mock JWT token
     * 
     * @param token The JWT token to validate
     * @return The decoded JWT if valid
     * @throws JWTVerificationException If the token is invalid
     */
    public DecodedJWT validateToken(String token) throws JWTVerificationException {
        // In local development, we just decode the token without verifying the signature
        DecodedJWT jwt = JWT.decode(token);
        
        // Perform basic validation checks
        if (!jwt.getIssuer().equals(issuer)) {
            throw new JWTVerificationException("Invalid issuer");
        }
        
        if (!jwt.getAudience().contains(audience)) {
            throw new JWTVerificationException("Invalid audience");
        }
        
        // Check if the token is expired
        if (jwt.getExpiresAt() != null && jwt.getExpiresAt().before(new java.util.Date())) {
            throw new JWTVerificationException("Token is expired");
        }
        
        return jwt;
    }
}
