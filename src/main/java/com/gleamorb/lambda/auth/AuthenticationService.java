package com.gleamorb.lambda.auth;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Service for handling authentication and authorization
 */
public class AuthenticationService {
    private final CognitoJwtValidator jwtValidator;
    private final boolean isLocalEnvironment;
    private final MockTokenValidator mockValidator;
    
    /**
     * Constructor for the authentication service
     */
    public AuthenticationService() {
        // Check if we're running in a local environment
        this.isLocalEnvironment = isLocalEnvironment();
        
        // Get configuration from environment variables
        String userPoolId = System.getenv("COGNITO_USER_POOL_ID");
        String region = System.getenv("COGNITO_REGION");
        String appClientId = System.getenv("COGNITO_APP_CLIENT_ID");
        
        // Create the JWT validator
        if (isLocalEnvironment) {
            this.jwtValidator = null;
            this.mockValidator = new MockTokenValidator(region, userPoolId, appClientId);
        } else {
            this.jwtValidator = new CognitoJwtValidator(userPoolId, region, appClientId);
            this.mockValidator = null;
        }
    }
    
    /**
     * Validates a token from the Authorization header
     * 
     * @param authorizationHeader The Authorization header value
     * @return The decoded JWT if valid
     * @throws AuthenticationException If the token is invalid or missing
     */
    public DecodedJWT validateToken(String authorizationHeader) throws AuthenticationException {
        // Check if the header is present
        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            throw new AuthenticationException("Missing Authorization header");
        }
        
        // Extract the token from the header
        String token = extractToken(authorizationHeader);
        if (token == null) {
            throw new AuthenticationException("Invalid Authorization header format");
        }
        
        try {
            // Validate the token
            if (isLocalEnvironment) {
                return mockValidator.validateToken(token);
            } else {
                return jwtValidator.validateToken(token);
            }
        } catch (JWTVerificationException e) {
            throw new AuthenticationException("Invalid token: " + e.getMessage());
        }
    }
    
    /**
     * Extracts the token from the Authorization header
     * 
     * @param authorizationHeader The Authorization header value
     * @return The token, or null if not found
     */
    private String extractToken(String authorizationHeader) {
        // Check if the header starts with "Bearer "
        if (authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
    
    /**
     * Checks if we're running in a local environment
     * 
     * @return True if running locally, false otherwise
     */
    private boolean isLocalEnvironment() {
        // Check for SAM local environment
        String awsExecutionEnv = System.getenv("AWS_EXECUTION_ENV");
        String samLocalEnv = System.getenv("AWS_SAM_LOCAL");
        
        return (samLocalEnv != null && samLocalEnv.equals("true")) || 
               (awsExecutionEnv == null || awsExecutionEnv.isEmpty());
    }
    
    /**
     * Exception thrown when authentication fails
     */
    public static class AuthenticationException extends Exception {
        public AuthenticationException(String message) {
            super(message);
        }
    }
}
