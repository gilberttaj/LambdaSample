# GleamOrb Lambda Application

A Java-based AWS Lambda application for managing email destinations via a web interface, integrated with API Gateway.

## Project Structure

```
project-root/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/gleamorb/lambda/
│   │   │       ├── handlers/           # Lambda handlers
│   │   │       ├── models/             # Data models
│   │   │       ├── repositories/       # Database access
│   │   │       └── services/           # Business logic
│   │   └── resources/
│   └── test/
│       └── java/                       # Unit tests
├── template.yaml                       # SAM template
├── pom.xml                             # Maven dependencies
└── README.md                           # This file
```

## Prerequisites

- Java 17 (OpenJDK)
- Maven
- AWS CLI
- AWS SAM CLI
- Docker (for local testing)
- PostgreSQL (for local development)

## Local Development Setup

### 1. Install AWS CLI

1. Download the AWS CLI v2 installer for Windows:
   https://awscli.amazonaws.com/AWSCLIV2.msi

2. Run the installer and follow the prompts

3. Configure AWS CLI with your credentials:
   ```
   aws configure
   ```

### 2. Install AWS SAM CLI

1. Download the SAM CLI installer for Windows:
   https://github.com/aws/aws-sam-cli/releases/latest/download/AWS_SAM_CLI_64_PIP.msi

2. Run the installer and follow the prompts

3. Verify installation:
   ```
   sam --version
   ```

### 3. Set up Local Database

1. Install PostgreSQL or use Docker:
   ```
   docker run --name local-postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=gleamorb_db -p 5432:5432 -d postgres:14
   ```

2. Create the necessary tables (using psql or tool of your choice):
   ```sql
   CREATE TABLE email_destinations (
     id VARCHAR(36) PRIMARY KEY,
     user_id VARCHAR(50) NOT NULL,
     registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     approval_user VARCHAR(50),
     approval_date TIMESTAMP NULL,
     update_user VARCHAR(50),
     update_date TIMESTAMP NULL,
     display_code VARCHAR(20) NOT NULL,
     department_code VARCHAR(20),
     chain_code VARCHAR(20),
     input_method VARCHAR(20),
     receipt_type VARCHAR(20),
     processing_source_code VARCHAR(20),
     file_format VARCHAR(10),
     source_file_pattern VARCHAR(100),
     destination_directory VARCHAR(255),
     email_title VARCHAR(255),
     source_file_path VARCHAR(255),
     destination_file_path VARCHAR(255),
     auto_resend BOOLEAN DEFAULT false
   );

   CREATE TABLE email_destination_addresses (
     id SERIAL PRIMARY KEY,
     destination_id VARCHAR(36) NOT NULL,
     email_address VARCHAR(255) NOT NULL,
     FOREIGN KEY (destination_id) REFERENCES email_destinations(id) ON DELETE CASCADE
   );
   ```

### 4. Create Local Environment Variables

Create a `.env.local` file in the project root:

```
DB_URL=jdbc:postgresql://localhost:5432/gleamorb_db
DB_USER=postgres
DB_PASSWORD=password
```

## Building the Project

```
mvn clean package
```

## Authentication with AWS Cognito

This application uses AWS Cognito for authentication and authorization. The following endpoints are available for authentication:

- `POST /auth/signup` - Register a new user
- `POST /auth/login` - Login and get JWT tokens
- `GET /auth/mock-token` - Generate a mock JWT token for local testing

### Authentication Flow

1. Users register using the `/auth/signup` endpoint with the following fields:
   - `email`: Email address (required)
   - `password`: User's password (required)
   - `username`: Username (required)
   - `firstName`: User's first name (optional)
   - `lastName`: User's last name (optional)
2. Users login using the `/auth/login` endpoint to get JWT tokens
3. Users include the JWT token in the `Authorization` header for subsequent requests
4. The API Gateway authenticates requests using Cognito User Pool authorizer
5. Lambda functions validate the JWT token before processing requests

## Local Testing with SAM

1. Build with SAM:
   ```
   sam build
   ```

2. Start a local API:
   ```
   sam local start-api
   ```

3. Get a mock token for testing (when running locally):
   ```
   curl http://localhost:3000/auth/mock-token?username=testuser&email=test@example.com
   ```

4. Use the mock token to authenticate API requests:
   ```
   curl -X POST http://localhost:3000/api/email-destinations/register -d '{...your JSON data...}' -H "Content-Type: application/json" -H "Authorization: Bearer YOUR_MOCK_TOKEN"
   ```

### Testing Auth Endpoints Locally

1. Test signup (local environment will simulate success):
   ```
   curl -X POST http://localhost:3000/auth/signup \
     -H "Content-Type: application/json" \
     -d '{"username":"newuser","password":"Password123!","email":"user@example.com"}'
   ```

2. Test login (local environment will return a mock token):
   ```
   curl -X POST http://localhost:3000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"newuser","password":"Password123!"}'
   ```

## Deployment

Deploy using SAM:

```
sam deploy --guided
```

Follow the prompts to complete the deployment.

## AWS Services Used

- AWS Lambda - For serverless computing
- Amazon RDS - For database storage
- Amazon API Gateway - For REST API endpoints
- AWS Cognito - For authentication and authorization
- AWS AppRunner - For web UI (separate repository)

## Architecture

This application follows the architecture shown in the project documentation, featuring:
- Lambda functions for business logic
- API Gateway for RESTful endpoints
- RDS for data persistence
- Cognito for authentication
