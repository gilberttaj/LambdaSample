package com.gleamorb.lambda.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

/**
 * Generates mock JWT tokens for local testing
 */
public class MockTokenGenerator {
    private static final long TOKEN_EXPIRY = 3600000; // 1 hour in milliseconds
    private final Algorithm algorithm;
    private final String issuer;
    private final String audience;
    
    /**
     * Constructor for the mock token generator
     * 
     * @param region The AWS region to use in the mock issuer
     * @param userPoolId The Cognito User Pool ID to use in the mock issuer
     * @param appClientId The App Client ID to use as the audience
     */
    public MockTokenGenerator(String region, String userPoolId, String appClientId) {
        try {
            // Generate a key pair for signing the tokens
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            
            // Create the algorithm with the key pair
            this.algorithm = Algorithm.RSA256(publicKey, privateKey);
            
            // Set the issuer and audience
            this.issuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
            this.audience = appClientId;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }
    
    /**
     * Generates a mock JWT token
     * 
     * @param username The username to include in the token
     * @param email The email to include in the token
     * @param groups Optional groups to include in the token
     * @return The JWT token
     */
    public String generateToken(String username, String email, String... groups) {
        long now = System.currentTimeMillis();
        
        // Build the token
        return JWT.create()
                .withIssuer(issuer)
                .withAudience(audience)
                .withIssuedAt(new Date(now))
                .withExpiresAt(new Date(now + TOKEN_EXPIRY))
                .withSubject(username)
                .withClaim("email", email)
                .withClaim("cognito:username", username)
                .withArrayClaim("cognito:groups", groups)
                .withJWTId(UUID.randomUUID().toString())
                .withKeyId("mock-key-id")
                .sign(algorithm);
    }
    
    /**
     * Main method for generating a mock token from the command line
     */
    public static void main(String[] args) {
        // Get environment variables or use defaults
        String region = System.getenv("COGNITO_REGION") != null ? 
                        System.getenv("COGNITO_REGION") : "us-east-1";
        String userPoolId = System.getenv("COGNITO_USER_POOL_ID") != null ? 
                           System.getenv("COGNITO_USER_POOL_ID") : "us-east-1_mockpool";
        String appClientId = System.getenv("COGNITO_APP_CLIENT_ID") != null ? 
                            System.getenv("COGNITO_APP_CLIENT_ID") : "mockclientid";
        
        // Create the generator
        MockTokenGenerator generator = new MockTokenGenerator(region, userPoolId, appClientId);
        
        // Generate a token
        String token = generator.generateToken("testuser", "test@example.com", "admin");
        
        // Print the token
        System.out.println("Mock JWT Token for local testing:");
        System.out.println(token);
    }
}
