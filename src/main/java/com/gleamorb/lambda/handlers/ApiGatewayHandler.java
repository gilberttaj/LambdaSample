package com.gleamorb.lambda.handlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * Main Lambda handler for API Gateway requests
 * This handler processes web requests for database operations (register, edit, delete)
 */
public class ApiGatewayHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    
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
            } else if ("PUT".equals(httpMethod) && path.contains("/edit")) {
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
        // TODO: Implement actual registration logic with database
        Map<String, String> result = new HashMap<>();
        result.put("status", "success");
        result.put("message", "Registration successful");
        result.put("requestBody", input.getBody());
        
        response.setStatusCode(201); // Created
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleEdit(APIGatewayProxyRequestEvent input, 
                                                 APIGatewayProxyResponseEvent response) {
        // TODO: Implement actual edit logic with database
        Map<String, String> result = new HashMap<>();
        result.put("status", "success");
        result.put("message", "Edit successful");
        result.put("requestBody", input.getBody());
        
        response.setStatusCode(200); // OK
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleDelete(APIGatewayProxyRequestEvent input, 
                                                   APIGatewayProxyResponseEvent response) {
        // TODO: Implement actual delete logic with database
        String pathParam = input.getPathParameters() != null ? 
                           input.getPathParameters().get("id") : "unknown";
        
        Map<String, String> result = new HashMap<>();
        result.put("status", "success");
        result.put("message", "Delete successful for ID: " + pathParam);
        
        response.setStatusCode(200); // OK
        response.setBody(gson.toJson(result));
        return response;
    }
    
    private APIGatewayProxyResponseEvent handleList(APIGatewayProxyResponseEvent response) {
        // TODO: Implement actual listing logic with database
        Map<String, String> result = new HashMap<>();
        result.put("status", "success");
        result.put("data", "[]"); // Placeholder for actual data
        
        response.setStatusCode(200); // OK
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
