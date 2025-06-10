package com.gleamorb.lambda.handlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.gleamorb.lambda.auth.MockTokenGenerator;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Handler for authentication endpoints (signup, login, mock-token)
 */
public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    // Create Gson instance with custom adapter for handling java.time.Instant
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .registerTypeAdapter(java.time.Instant.class, new InstantTypeAdapter())
            .create();
            
    /**
     * Custom TypeAdapter for java.time.Instant to handle serialization
     */
    private static class InstantTypeAdapter extends com.google.gson.TypeAdapter<java.time.Instant> {
        @Override
        public void write(com.google.gson.stream.JsonWriter out, java.time.Instant value) throws java.io.IOException {
            if (value == null) {
                out.nullValue();
            } else {
                out.value(value.toString());
            }
        }

        @Override
        public java.time.Instant read(com.google.gson.stream.JsonReader in) throws java.io.IOException {
            if (in.peek() == com.google.gson.stream.JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            return java.time.Instant.parse(in.nextString());
        }
    }
    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;
    private final String appClientId;
    private final boolean isLocalEnvironment;

    /**
     * Constructor for the auth handler
     */
    public AuthHandler() {
        // Check if we're running in a local environment
        this.isLocalEnvironment = isLocalEnvironment();
        
        // Get configuration from environment variables
        this.userPoolId = System.getenv("COGNITO_USER_POOL_ID");
        this.appClientId = System.getenv("COGNITO_APP_CLIENT_ID");
        String region = System.getenv("COGNITO_REGION");
        
        // Create the Cognito client if not in local environment
        if (isLocalEnvironment) {
            this.cognitoClient = null;
        } else {
            this.cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.of(region))
                    .build();
        }
    }
    
    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        context.getLogger().log("Input received: " + input);
        
        // Get the HTTP method and path
        String httpMethod = input.getHttpMethod();
        String path = input.getPath();
        
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(getResponseHeaders());
        response.setStatusCode(200); // Set default status code
        
        try {
            // Route the request based on path
            if ("POST".equals(httpMethod) && path.contains("/auth/signup")) {
                return handleSignup(input, response, context);
            } else if ("POST".equals(httpMethod) && path.contains("/auth/login")) {
                return handleLogin(input, response, context);
            } else if ("GET".equals(httpMethod) && path.contains("/auth/mock-token")) {
                return handleMockToken(input, response, context);
            } else if ("GET".equals(httpMethod) && path.contains("/auth/google/callback")) {
                return handleGoogleCallback(input, response, context);
            } else if ("GET".equals(httpMethod) && path.contains("/auth/google") && !path.contains("/callback")) {
                return handleGoogleAuth(input, response, context);
            } else {
                response.setStatusCode(404);
                response.setBody("Not Found: " + path);
                return response;
            }
        } catch (Exception e) {
            e.printStackTrace();
            context.getLogger().log("Error handling request: " + e.getMessage());
            response.setStatusCode(500);
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "Internal server error: " + e.getMessage());
            responseBody.put("path", path);
            responseBody.put("method", httpMethod);
            response.setBody(gson.toJson(responseBody));
            return response;
        }
    }
    
    /**
     * Handles signup requests
     */
    private APIGatewayProxyResponseEvent handleSignup(APIGatewayProxyRequestEvent input, 
                                                    APIGatewayProxyResponseEvent response, 
                                                    Context context) {
        // Parse the request body
        JsonObject requestBody = JsonParser.parseString(input.getBody()).getAsJsonObject();
        String username = requestBody.get("username").getAsString();
        String password = requestBody.get("password").getAsString();
        String email = requestBody.get("email").getAsString();
        String firstName = requestBody.has("firstName") ? requestBody.get("firstName").getAsString() : null;
        String lastName = requestBody.has("lastName") ? requestBody.get("lastName").getAsString() : null;
        
        // Log the parsed fields
        context.getLogger().log("Signup fields - email: " + email + ", firstName: " + firstName + ", lastName: " + lastName);
        
        // Log the request
        context.getLogger().log("Signup request for username: " + username);
        
        if (isLocalEnvironment) {
            // In local environment, just return success
            context.getLogger().log("Local environment detected, simulating signup success");
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("message", "User registered successfully (mock)");
            responseBody.put("username", username);
            if (firstName != null) responseBody.put("firstName", firstName);
            if (lastName != null) responseBody.put("lastName", lastName);
            response.setStatusCode(200);
            response.setBody(gson.toJson(responseBody));
            return response;
        } 
        
        // IMPORTANT: Since Cognito is configured to use email as username,
        // we need to use the email as the username to avoid validation errors
        String cognitoUsername = email; // Always use email as username with Cognito
        
        // Log the username change if applicable
        if (!username.equals(email)) {
            context.getLogger().log("Using email as username for Cognito: " + email);
        }
        
        // First, check if the user already exists
        try {
            AdminGetUserRequest getUserRequest = AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cognitoUsername)
                    .build();
            
            AdminGetUserResponse userResponse = cognitoClient.adminGetUser(getUserRequest);
            context.getLogger().log("User already exists with status: " + userResponse.userStatusAsString());
            
            // User exists, return an appropriate message
            Map<String, Object> resultBody = new HashMap<>();
            resultBody.put("status", "error");
            resultBody.put("message", "User already exists with this email address");
            response.setStatusCode(400);
            response.setBody(gson.toJson(resultBody));
            return response;
        } catch (UserNotFoundException e) {
            // User doesn't exist, proceed with creation
            context.getLogger().log("User doesn't exist, creating new user: " + cognitoUsername);
        } catch (Exception e) {
            // Log any other error when checking if user exists
            context.getLogger().log("Error checking if user exists: " + e.getMessage());
            // Return error response
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Error checking if user exists: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody(gson.toJson(errorResponse));
            return response;
        }
        
        // Try to create the user
        try {
            // Create the user in Cognito with email as username
            AdminCreateUserRequest createUserRequest = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cognitoUsername) // Use email here
                    .temporaryPassword(password)
                    .userAttributes(
                            AttributeType.builder().name("email").value(email).build(),
                            AttributeType.builder().name("email_verified").value("true").build(),
                            // Store original username in the preferred_username standard attribute if different
                            username.equals(email) ? null : AttributeType.builder().name("preferred_username").value(username).build(),
                            // Add firstName and lastName if provided
                            firstName != null ? AttributeType.builder().name("given_name").value(firstName).build() : null,
                            lastName != null ? AttributeType.builder().name("family_name").value(lastName).build() : null
                    )
                    .messageAction(MessageActionType.SUPPRESS) // Don't send welcome email
                    .build();
            
            AdminCreateUserResponse createUserResult = cognitoClient.adminCreateUser(createUserRequest);
            
            // Set the user's password
            AdminSetUserPasswordRequest setPasswordRequest = AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cognitoUsername) // Use email as username
                    .password(password)
                    .permanent(true)
                    .build();
            
            cognitoClient.adminSetUserPassword(setPasswordRequest);
            
            // Explicitly confirm the user after setting password
            try {
                AdminConfirmSignUpRequest confirmSignUpRequest = AdminConfirmSignUpRequest.builder()
                        .userPoolId(userPoolId)
                        .username(cognitoUsername)
                        .build();
                
                cognitoClient.adminConfirmSignUp(confirmSignUpRequest);
                context.getLogger().log("User confirmed successfully: " + cognitoUsername);
            } catch (Exception confirmException) {
                // Log the exception but continue - user is still created
                context.getLogger().log("Warning: Could not confirm user but continuing: " + confirmException.getMessage());
            }
        
            // Extract only necessary information from the user object to avoid serialization issues
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("username", createUserResult.user().username());
            userDetails.put("status", createUserResult.user().userStatus().toString());
            userDetails.put("created_at", createUserResult.user().userCreateDate().toString());
            // Add firstName and lastName to response if they were provided
            if (firstName != null) userDetails.put("firstName", firstName);
            if (lastName != null) userDetails.put("lastName", lastName);
            
            // Return success response with simplified user object
            Map<String, Object> resultBody = new HashMap<>();
            resultBody.put("status", "success");
            resultBody.put("message", "User registered successfully");
            resultBody.put("user", userDetails);
            response.setStatusCode(200);
            response.setBody(gson.toJson(resultBody));
            return response;
        } catch (UsernameExistsException e) {
            // Return error response
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Username already exists");
            response.setStatusCode(400);
            response.setBody(gson.toJson(errorResponse));
            return response;
        } catch (Exception e) {
            // Return error response
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", e.getMessage());
            response.setStatusCode(500);
            response.setBody(gson.toJson(errorResponse));
            return response;
        }
    }
    
    /**
     * Handles login requests
     */
    private APIGatewayProxyResponseEvent handleLogin(APIGatewayProxyRequestEvent input, 
                                                   APIGatewayProxyResponseEvent response, 
                                                   Context context) {
        // Parse the request body
        JsonObject requestBody = JsonParser.parseString(input.getBody()).getAsJsonObject();
        String username = requestBody.get("username").getAsString();
        String password = requestBody.get("password").getAsString();
        
        // Log the request
        context.getLogger().log("Login request for username: " + username);
        
        if (isLocalEnvironment) {
            // In local environment, generate a mock token
            context.getLogger().log("Local environment detected, generating mock token");
            String mockToken = generateMockToken(username, username + "@example.com");
            
            // Return success response with mock token
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("message", "Login successful (mock)");
            responseBody.put("id_token", mockToken);
            responseBody.put("access_token", mockToken);
            responseBody.put("refresh_token", "mock-refresh-token");
            responseBody.put("expires_in", 3600);
            responseBody.put("token_type", "Bearer");
            response.setStatusCode(200);
            response.setBody(gson.toJson(responseBody));
            return response;
        } else {
            try {
                // Authenticate with Cognito
                Map<String, String> authParams = new HashMap<>();
                authParams.put("USERNAME", username);
                authParams.put("PASSWORD", password);
                
                AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                        .userPoolId(userPoolId)
                        .clientId(appClientId)
                        .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                        .authParameters(authParams)
                        .build();
                
                AdminInitiateAuthResponse authResult = cognitoClient.adminInitiateAuth(authRequest);
                
                // Return success response with tokens
                Map<String, Object> responseBody = new HashMap<>();
                responseBody.put("status", "success");
                responseBody.put("message", "Login successful");
                responseBody.put("id_token", authResult.authenticationResult().idToken());
                responseBody.put("access_token", authResult.authenticationResult().accessToken());
                responseBody.put("refresh_token", authResult.authenticationResult().refreshToken());
                responseBody.put("expires_in", authResult.authenticationResult().expiresIn());
                responseBody.put("token_type", "Bearer");
                response.setStatusCode(200);
                response.setBody(gson.toJson(responseBody));
                return response;
            } catch (NotAuthorizedException e) {
                // Return error response
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", "Invalid username or password");
                response.setStatusCode(401);
                response.setBody(gson.toJson(errorResponse));
                return response;
            } catch (UserNotFoundException e) {
                // Return error response
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", "User not found");
                response.setStatusCode(404);
                response.setBody(gson.toJson(errorResponse));
                return response;
            } catch (Exception e) {
                // Return error response
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", e.getMessage());
                response.setStatusCode(500);
                response.setBody(gson.toJson(errorResponse));
                return response;
            }
        }
    }
    
    /**
     * Handles mock token requests
     */
    private APIGatewayProxyResponseEvent handleMockToken(APIGatewayProxyRequestEvent input, 
                                                       APIGatewayProxyResponseEvent response, 
                                                       Context context) {
        // Get query parameters
        Map<String, String> queryParams = input.getQueryStringParameters();
        String username = queryParams != null ? queryParams.get("username") : "testuser";
        String email = queryParams != null ? queryParams.get("email") : username + "@example.com";
        
        // Log the request
        context.getLogger().log("Mock token request for username: " + username);
        
        // Generate a mock token
        String mockToken = generateMockToken(username, email);
        
        // Return success response with mock token
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "success");
        responseBody.put("message", "Mock token generated");
        responseBody.put("id_token", mockToken);
        responseBody.put("access_token", mockToken);
        responseBody.put("refresh_token", "mock-refresh-token");
        responseBody.put("expires_in", 3600);
        responseBody.put("token_type", "Bearer");
        response.setStatusCode(200);
        response.setBody(gson.toJson(responseBody));
        return response;
    }
    
    /**
     * Generates a mock JWT token
     */
    private String generateMockToken(String username, String email) {
        // Get configuration from environment variables
        String region = System.getenv("COGNITO_REGION") != null ? 
                        System.getenv("COGNITO_REGION") : "us-east-1";
        String userPoolId = System.getenv("COGNITO_USER_POOL_ID") != null ? 
                           System.getenv("COGNITO_USER_POOL_ID") : "us-east-1_mockpool";
        String appClientId = System.getenv("COGNITO_APP_CLIENT_ID") != null ? 
                            System.getenv("COGNITO_APP_CLIENT_ID") : "mockclientid";
        
        // Create the generator
        MockTokenGenerator generator = new MockTokenGenerator(region, userPoolId, appClientId);
        
        // Generate a token
        return generator.generateToken(username, email);
    }
    
    /**
     * Checks if we're running in a local environment
     */
    private boolean isLocalEnvironment() {
        // Check for SAM local environment
        String awsExecutionEnv = System.getenv("AWS_EXECUTION_ENV");
        String samLocalEnv = System.getenv("AWS_SAM_LOCAL");
        
        return (samLocalEnv != null && samLocalEnv.equals("true")) || 
               (awsExecutionEnv == null || awsExecutionEnv.isEmpty());
    }
    
    /**
     * Returns the response headers
     */
    private Map<String, String> getResponseHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Access-Control-Allow-Origin", "*");
        headers.put("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.put("Access-Control-Allow-Headers", "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token");
        return headers;
    }
    
    /**
     * Generate a code verifier for PKCE (Proof Key for Code Exchange)
     * The code verifier should be a random string of between 43 and 128 characters
     */
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }
    
    /**
     * Generate a code challenge from the code verifier using S256
     * @param codeVerifier The code verifier to generate challenge from
     * @return Base64URL encoded SHA-256 hash of the code verifier
     */
    private String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes("US-ASCII");
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Initiates Google authentication
     */
    private APIGatewayProxyResponseEvent handleGoogleAuth(APIGatewayProxyRequestEvent input, 
                                                      APIGatewayProxyResponseEvent response, 
                                                      Context context) {
        try {
            
            // Get Cognito domain URL - using the fixed domain
            String cognitoDomainUrl = "https://nais.auth.ap-northeast-1.amazoncognito.com";
            
            // Generate PKCE code verifier and challenge
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            
            // Generate a state that contains the code verifier (in a real app, store this securely)
            // We'll encode the code verifier in the state and retrieve it in the callback
            String state = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier.getBytes());
            context.getLogger().log("State with code verifier: " + state);
            context.getLogger().log("Code verifier: " + codeVerifier);
            
            // Construct the redirect URL to Cognito's OAuth endpoint with Google as the provider
            // Include PKCE parameters required by Cognito and state to pass the code verifier
            String redirectUrl = String.format("%s/oauth2/authorize?response_type=code&client_id=%s" +
                    "&redirect_uri=%s&identity_provider=Google&scope=email+openid+profile" +
                    "&code_challenge=%s&code_challenge_method=S256&state=%s",
                    cognitoDomainUrl,
                    appClientId,
                    java.net.URLEncoder.encode("https://71yru8o4n5.execute-api.ap-northeast-1.amazonaws.com/Prod/auth/google/callback", "UTF-8"),
                    codeChallenge,
                    java.net.URLEncoder.encode(state, "UTF-8"));
            
            // Return the redirect URL in the response body instead of doing a 302 redirect
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("redirectUrl", redirectUrl);
            
            response.setStatusCode(200); // Use 200 instead of 302 to avoid CORS issues
            response.setHeaders(getResponseHeaders()); // Use standard CORS headers
            response.setBody(gson.toJson(responseBody));
            return response;
        } catch (Exception e) {
            context.getLogger().log("Error initiating Google auth: " + e.getMessage());
            response.setStatusCode(500);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Failed to initiate Google authentication: " + e.getMessage());
            response.setBody(gson.toJson(errorResponse));
            return response;
        }
    }
    
    /**
     * Handles the callback from Google OAuth flow
     */
    private APIGatewayProxyResponseEvent handleGoogleCallback(APIGatewayProxyRequestEvent input, 
                                                     APIGatewayProxyResponseEvent response, 
                                                     Context context) 
    {
        try {
            context.getLogger().log("Received Google callback: " + input.toString());
            context.getLogger().log("Query parameters: " + (input.getQueryStringParameters() != null ? input.getQueryStringParameters().toString() : "null"));
            
            Map<String, String> queryParams = input.getQueryStringParameters();
            if (queryParams == null) {
                queryParams = new HashMap<>();
            }
            
            // Try to get auth code from multiple possible locations
            String authCode = null;
            
            // First check the query parameters
            if (queryParams.containsKey("code")) {
                authCode = queryParams.get("code");
            }
            
            // If not found, check path parameters
            if ((authCode == null || authCode.isEmpty()) && input.getPathParameters() != null) {
                Map<String, String> pathParams = input.getPathParameters();
                if (pathParams.containsKey("code")) {
                    authCode = pathParams.get("code");
                }
            }
            
            // If still not found, check multi-value query parameters
            if ((authCode == null || authCode.isEmpty()) && input.getMultiValueQueryStringParameters() != null) {
                Map<String, java.util.List<String>> multiValueParams = input.getMultiValueQueryStringParameters();
                if (multiValueParams.containsKey("code") && !multiValueParams.get("code").isEmpty()) {
                    authCode = multiValueParams.get("code").get(0);
                }
            }
            
            // Check if we have a valid auth code now
            if (authCode == null || authCode.trim().isEmpty()) {
                response.setStatusCode(400);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", "No authorization code provided");
                response.setBody(gson.toJson(errorResponse));
                return response;
            }
            
            // Extract the state parameter which contains our encoded code verifier
            String state = queryParams.get("state");
            String codeVerifier = null;
            
            if (state != null && !state.isEmpty()) {
                try {
                    // Decode the state to get the code verifier
                    codeVerifier = new String(Base64.getUrlDecoder().decode(state));
                    context.getLogger().log("Extracted code verifier from state: " + codeVerifier);
                } catch (Exception e) {
                    context.getLogger().log("Error decoding state parameter: " + e.getMessage());
                }
            }
            
            // For local development, generate a mock token
            if (isLocalEnvironment || "LOCAL_DEV_CODE".equals(authCode)) {
                String email = queryParams.containsKey("email") ? queryParams.get("email") : "googleuser@example.com";
                String username = email.split("@")[0]; // Extract username from email
                
                String mockToken = generateMockToken(username, email);
                
                // Return success response with mock token
                Map<String, Object> responseBody = new HashMap<>();
                responseBody.put("status", "success");
                responseBody.put("message", "Google login successful (mock)");
                responseBody.put("id_token", mockToken);
                responseBody.put("access_token", mockToken);
                responseBody.put("refresh_token", "mock-refresh-token");
                responseBody.put("expires_in", 3600);
                responseBody.put("token_type", "Bearer");
                
                // We can either return JSON directly or redirect to the frontend with token as a parameter
                // For simplicity in local development, we'll just return the token as JSON
                response.setStatusCode(200);
                response.setBody(gson.toJson(responseBody));
                return response;
            }
            
            // Exchange the authorization code for tokens
            Map<String, String> tokenRequest = new HashMap<>();
            tokenRequest.put("grant_type", "authorization_code");
            tokenRequest.put("client_id", appClientId);
            tokenRequest.put("code", authCode);
            
            // Get client secret from environment variables
            String appClientSecret = System.getenv("COGNITO_APP_CLIENT_SECRET");
            if (appClientSecret != null && !appClientSecret.isEmpty()) {
                // For AWS Cognito, it's preferred to include client_secret in the body
                tokenRequest.put("client_secret", appClientSecret);
                context.getLogger().log("Added client_secret to token request body");
            } else {
                context.getLogger().log("WARNING: No client_secret available in environment variables");
                context.getLogger().log("Client secret is required for token exchange with Cognito");
            }
            
            // IMPORTANT: The redirect_uri must match EXACTLY what was used in the authorization request
            // For now, we know it's always the localhost URL in the initial authorization request
            // based on the frontend code and authorization URL
            String redirectUri = "https://71yru8o4n5.execute-api.ap-northeast-1.amazonaws.com/Prod/auth/google/callback";
            context.getLogger().log("Using redirect URI: " + redirectUri);
            
            // Set the redirect URI
            tokenRequest.put("redirect_uri", redirectUri);
            
            // Log the token request parameters for debugging (hiding the client secret)
            Map<String, String> logSafeParams = new HashMap<>(tokenRequest);
            if (logSafeParams.containsKey("client_secret")) {
                logSafeParams.put("client_secret", "[REDACTED]");
            }
            context.getLogger().log("Token request parameters: " + logSafeParams.toString());
            
            // Add the code_verifier for PKCE if available
            if (codeVerifier != null) {
                tokenRequest.put("code_verifier", codeVerifier);
                context.getLogger().log("Added code_verifier to token request");
            } else {
                context.getLogger().log("WARNING: No code_verifier available for PKCE");                
            }
            
            // Get Cognito domain URL
            String cognitoDomainUrl = "https://nais.auth.ap-northeast-1.amazoncognito.com";
                    
            // Now exchange the auth code for tokens
            URL tokenUrl = new URL(cognitoDomainUrl + "/oauth2/token");
            context.getLogger().log("Token URL: " + tokenUrl.toString());
            
            HttpURLConnection tokenConnection = (HttpURLConnection) tokenUrl.openConnection();
            tokenConnection.setRequestMethod("POST");
            tokenConnection.setConnectTimeout(10000);  // 10 seconds timeout
            tokenConnection.setReadTimeout(10000);     // 10 seconds read timeout
            tokenConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            tokenConnection.setRequestProperty("Accept", "application/json");
            tokenConnection.setDoOutput(true);
            
            // For Cognito, client credentials in the body are generally sufficient
            // Only add Authorization header if explicitly needed
            String clientSecret = appClientSecret; // Use the one we already retrieved
            boolean useBasicAuth = false; // Set to true only if needed
            
            if (useBasicAuth && clientSecret != null && !clientSecret.isEmpty()) {
                String clientAuth = appClientId + ":" + clientSecret;
                String encodedClientAuth = Base64.getEncoder().encodeToString(clientAuth.getBytes());
                tokenConnection.setRequestProperty("Authorization", "Basic " + encodedClientAuth);
                context.getLogger().log("Added Authorization header with Basic auth");
            }
            
            StringBuilder tokenParams = new StringBuilder();
            for (Map.Entry<String, String> entry : tokenRequest.entrySet()) {
                if (tokenParams.length() > 0) {
                    tokenParams.append("&");
                }
                tokenParams.append(entry.getKey())
                    .append("=")
                    .append(java.net.URLEncoder.encode(entry.getValue(), "UTF-8"));
            }
            
            try (OutputStream os = tokenConnection.getOutputStream()) {
                byte[] requestData = tokenParams.toString().getBytes("UTF-8");
                os.write(requestData, 0, requestData.length);
            }
            
            int statusCode = tokenConnection.getResponseCode();
            
            java.io.InputStream inputStream;
            if (statusCode >= 400) {
                inputStream = tokenConnection.getErrorStream();
            } else {
                inputStream = tokenConnection.getInputStream();
            }
            
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(inputStream, "UTF-8"));
            StringBuilder responseBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                responseBuilder.append(line);
            }
            
            String responseContent = responseBuilder.toString();
            context.getLogger().log("Token endpoint response: " + responseContent);
            
            if (statusCode >= 400) {
                response.setStatusCode(statusCode);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", "Token exchange failed: " + responseContent);
                response.setBody(gson.toJson(errorResponse));
                return response;
            }
            
            // Parse the JSON response
            JsonObject tokenResponse = JsonParser.parseString(responseContent).getAsJsonObject();
            
            // Return success response with tokens
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("message", "Google login successful");
            responseBody.put("id_token", tokenResponse.get("id_token").getAsString());
            responseBody.put("access_token", tokenResponse.get("access_token").getAsString());
            if (tokenResponse.has("refresh_token")) {
                responseBody.put("refresh_token", tokenResponse.get("refresh_token").getAsString());
            }
            responseBody.put("expires_in", tokenResponse.get("expires_in").getAsInt());
            responseBody.put("token_type", tokenResponse.get("token_type").getAsString());
            
            response.setStatusCode(200);
            response.setBody(gson.toJson(responseBody));
            return response;
        } catch (Exception e) {
            context.getLogger().log("Error exchanging Google auth code for tokens: " + e.getMessage());
            e.printStackTrace();
            
            response.setStatusCode(500);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Failed to exchange auth code for tokens: " + e.getMessage());
            response.setBody(gson.toJson(errorResponse));
            return response;
        }
    }
}
