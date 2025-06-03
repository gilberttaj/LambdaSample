package com.gleamorb.lambda.handlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.gleamorb.lambda.models.EmailDestination;
import com.gleamorb.lambda.repositories.EmailDestinationRepository;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Main Lambda handler for API Gateway requests
 * This handler processes web requests for database operations (register, edit, delete)
 */
public class ApiGatewayHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final EmailDestinationRepository repository = new EmailDestinationRepository();
    
    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        context.getLogger().log("Input received: " + input);
        
        // Get the HTTP method to determine operation type
        String httpMethod = input.getHttpMethod();
        String path = input.getPath();
        
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(getResponseHeaders());
        
        try {
            // Route the request based on HTTP method and path
            if ("POST".equals(httpMethod) && path.contains("/register")) {
                return handleRegistration(input, response);
            } else if ("PUT".equals(httpMethod) && path.contains("/edit/")) {
                return handleEdit(input, response);
            } else if ("DELETE".equals(httpMethod) && path.contains("/delete")) {
                return handleDelete(input, response);
            } else if ("GET".equals(httpMethod) && path.contains("/list")) {
                return handleList(response);
            } else {
                // Return 404 for unknown routes
                response.setStatusCode(404);
                response.setBody("Not Found: " + path);
                return response;
            }
        } catch (Exception e) {
            context.getLogger().log("Error processing request: " + e.getMessage());
            response.setStatusCode(500);
            response.setBody("Internal Server Error: " + e.getMessage());
            return response;
        }
    }
    
    private APIGatewayProxyResponseEvent handleRegistration(APIGatewayProxyRequestEvent input, 
                                                         APIGatewayProxyResponseEvent response) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Parse the request body into EmailDestination object
            EmailDestination emailDestination = gson.fromJson(input.getBody(), EmailDestination.class);
            
            // Generate a UUID for the new record
            emailDestination.setId(UUID.randomUUID().toString());
            
            // Save to database
            boolean success = repository.create(emailDestination);
            
            if (success) {
                result.put("status", "success");
                result.put("message", "Registration successful");
                result.put("id", emailDestination.getId());
                response.setStatusCode(201); // Created
            } else {
                result.put("status", "error");
                result.put("message", "Failed to register email destination");
                response.setStatusCode(500); // Internal Server Error
            }
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Error processing request: " + e.getMessage());
            response.setStatusCode(400); // Bad Request
        }
        
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleEdit(APIGatewayProxyRequestEvent input, 
                                                 APIGatewayProxyResponseEvent response) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Get the ID from path parameters
            String id = input.getPathParameters() != null ? 
                      input.getPathParameters().get("id") : null;
            
            if (id == null || id.isEmpty()) {
                result.put("status", "error");
                result.put("message", "Missing ID parameter");
                response.setStatusCode(400); // Bad Request
                response.setBody(gson.toJson(result));
                return response;
            }
            
            // Parse the request body into EmailDestination object
            EmailDestination emailDestination = gson.fromJson(input.getBody(), EmailDestination.class);
            
            // Ensure the ID from the path is used
            emailDestination.setId(id);
            
            // Update in database
            boolean success = repository.update(emailDestination);
            
            if (success) {
                result.put("status", "success");
                result.put("message", "Edit successful");
                result.put("id", emailDestination.getId());
                response.setStatusCode(200); // OK
            } else {
                result.put("status", "error");
                result.put("message", "Failed to update email destination or record not found");
                response.setStatusCode(404); // Not Found
            }
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Error processing request: " + e.getMessage());
            response.setStatusCode(400); // Bad Request
        }
        
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleDelete(APIGatewayProxyRequestEvent input, 
                                                   APIGatewayProxyResponseEvent response) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Get the ID from path parameters
            String id = input.getPathParameters() != null ? 
                       input.getPathParameters().get("id") : null;
            
            if (id == null || id.isEmpty()) {
                result.put("status", "error");
                result.put("message", "Missing ID parameter");
                response.setStatusCode(400); // Bad Request
                response.setBody(gson.toJson(result));
                return response;
            }
            
            // Delete from database
            boolean success = repository.delete(id);
            
            if (success) {
                result.put("status", "success");
                result.put("message", "Delete successful for ID: " + id);
                response.setStatusCode(200); // OK
            } else {
                result.put("status", "error");
                result.put("message", "Failed to delete email destination or record not found");
                response.setStatusCode(404); // Not Found
            }
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Error processing request: " + e.getMessage());
            response.setStatusCode(500); // Internal Server Error
        }
        
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleList(APIGatewayProxyResponseEvent response) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Get all records from database
            List<EmailDestination> destinations = repository.findAll();
            
            result.put("status", "success");
            result.put("data", destinations);
            response.setStatusCode(200); // OK
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Error retrieving email destinations: " + e.getMessage());
            response.setStatusCode(500); // Internal Server Error
        }
        
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private Map<String, String> getResponseHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "GleamOrb Lambda Application");
        headers.put("Access-Control-Allow-Origin", "*");
        headers.put("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        headers.put("Access-Control-Allow-Headers", "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token");
        return headers;
    }
}
