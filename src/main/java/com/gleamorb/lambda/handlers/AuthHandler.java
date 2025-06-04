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
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;

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
        
        try {
            // Route the request based on path
            if ("POST".equals(httpMethod) && path.contains("/auth/signup")) {
                return handleSignup(input, response, context);
            } else if ("POST".equals(httpMethod) && path.contains("/auth/login")) {
                return handleLogin(input, response, context);
            } else if ("GET".equals(httpMethod) && path.contains("/auth/mock-token")) {
                return handleMockToken(input, response, context);
            } else {
                response.setStatusCode(404);
                response.setBody("Not Found: " + path);
                return response;
            }
        } catch (Exception e) {
            context.getLogger().log("Error processing request: " + e.getMessage());
            response.setStatusCode(500);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Internal Server Error: " + e.getMessage());
            response.setBody(gson.toJson(errorResponse));
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
        headers.put("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        headers.put("Access-Control-Allow-Headers", "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token");
        return headers;
    }
}
