package com.gleamorb.lambda.auth;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Validates JWT tokens issued by AWS Cognito
 */
public class CognitoJwtValidator {
    private final String userPoolId;
    private final String region;
    private final String appClientId;
    private final JwkProvider provider;
    private final Map<String, Algorithm> algorithmMap = new HashMap<>();

    /**
     * Constructor for the Cognito JWT validator
     * 
     * @param userPoolId The Cognito User Pool ID
     * @param region The AWS region where the User Pool is located
     * @param appClientId The App Client ID
     */
    public CognitoJwtValidator(String userPoolId, String region, String appClientId) {
        this.userPoolId = userPoolId;
        this.region = region;
        this.appClientId = appClientId;
        
        String jwksUrl = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId);
        try {
            this.provider = new UrlJwkProvider(new URL(jwksUrl));
        } catch (MalformedURLException e) {
            throw new RuntimeException("Invalid JWKS URL: " + jwksUrl, e);
        }
    }

    /**
     * Validates a JWT token
     * 
     * @param token The JWT token to validate
     * @return The decoded JWT if valid
     * @throws JWTVerificationException If the token is invalid
     */
    public DecodedJWT validateToken(String token) throws JWTVerificationException {
        try {
            // First decode the token to get the kid (key ID)
            DecodedJWT jwt = JWT.decode(token);
            
            // Check if token is from our user pool
            String issuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
            if (!jwt.getIssuer().equals(issuer)) {
                throw new JWTVerificationException("Invalid issuer");
            }
            
            // Check if token is for our app client
            if (!jwt.getAudience().contains(appClientId)) {
                throw new JWTVerificationException("Invalid audience");
            }
            
            // Get the algorithm for this key ID
            Algorithm algorithm = getAlgorithm(jwt.getKeyId());
            
            // Create a verifier for this algorithm
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(issuer)
                    .withAudience(appClientId)
                    .build();
            
            // Verify the token
            return verifier.verify(token);
        } catch (JwkException e) {
            throw new JWTVerificationException("Failed to get public key", e);
        }
    }
    
    /**
     * Get the algorithm for a specific key ID
     * 
     * @param kid The key ID
     * @return The algorithm
     * @throws JwkException If the key cannot be retrieved
     */
    private Algorithm getAlgorithm(String kid) throws JwkException {
        // Check if we already have the algorithm for this key ID
        if (algorithmMap.containsKey(kid)) {
            return algorithmMap.get(kid);
        }
        
        // Get the key from the provider
        Jwk jwk = provider.get(kid);
        
        // Create the algorithm
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        
        // Cache the algorithm
        algorithmMap.put(kid, algorithm);
        
        return algorithm;
    }
}
