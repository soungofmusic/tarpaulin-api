```markdown
# Tarpaulin API

A RESTful API for a lightweight course management tool called "Tarpaulin", an alternative to Canvas. This project serves as a portfolio piece demonstrating skills in building cloud-based APIs with proper authentication, authorization, and data management.

## Overview

Tarpaulin API provides a comprehensive set of endpoints for managing courses, users, and enrollments in an educational context. The API supports different user roles (admin, instructor, student) with appropriate permissions for each role.

## Features

- **User Authentication**: JWT-based authentication using Auth0
- **Role-Based Authorization**: Different permissions for admin, instructor, and student roles
- **Course Management**: Create, read, update, and delete courses
- **User Management**: User profile information and avatar handling
- **Student Enrollment**: Manage which students are enrolled in which courses
- **Cloud Storage**: Avatar images stored in Google Cloud Storage
- **Cloud Database**: Course and user data stored in Google Cloud Datastore
- **Pagination**: Support for offset/limit-based pagination

## Endpoints

### Authentication
- `POST /users/login` - Generate JWT token for authentication

### User Management
- `GET /users` - Get all users (admin only)
- `GET /users/:id` - Get detailed user information
- `POST /users/:id/avatar` - Upload user avatar image
- `GET /users/:id/avatar` - Retrieve user avatar image
- `DELETE /users/:id/avatar` - Delete user avatar

### Course Management
- `POST /courses` - Create a new course (admin only)
- `GET /courses` - Get paginated list of courses
- `GET /courses/:id` - Get detailed course information
- `PATCH /courses/:id` - Update course details (admin only)
- `DELETE /courses/:id` - Delete a course (admin only)

### Enrollment Management
- `PATCH /courses/:id/students` - Update student enrollment
- `GET /courses/:id/students` - Get enrolled students for a course

## Technology Stack

- **Language**: Python 3
- **Framework**: Flask
- **Database**: Google Cloud Datastore
- **Storage**: Google Cloud Storage
- **Authentication**: Auth0
- **Deployment**: Google App Engine

## Data Model

### User
- ID (auto-generated)
- Sub (Auth0 subject ID)
- Role (admin, instructor, or student)
- Courses (array of course IDs for instructors and students)
- Avatar status

### Course
- ID (auto-generated)
- Subject (e.g., "CS")
- Number (e.g., 493)
- Title (e.g., "Cloud Application Development")
- Term (e.g., "Fall 2024")
- Instructor ID
- Students (array of student IDs)

## Setup and Deployment

### Prerequisites
- Python 3.12+
- Google Cloud SDK
- Auth0 account

### Environment Setup
1. Clone this repository
2. Create a virtual environment: `python -m venv env`
3. Activate the environment: `source env/bin/activate` (Linux/Mac) or `env\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`

### Local Development
1. Configure environment variables in `.env` file:
   ```
   AUTH0_DOMAIN=your-auth0-domain.auth0.com
   API_AUDIENCE=your-api-audience
   CLIENT_ID=your-client-id
   CLIENT_SECRET=your-client-secret
   PROJECT_ID=your-gcp-project-id
   BUCKET_NAME=your-gcs-bucket-name
   ```
2. Run the development server: `python main.py`

### Deployment to Google App Engine
1. Update `app.yaml` with your configuration
2. Deploy using gcloud: `gcloud app deploy`

## Authentication

This API uses Auth0 for authentication. To access protected endpoints:
1. Obtain a JWT token by calling the login endpoint
2. Include the token in the Authorization header of subsequent requests:
   ```
   Authorization: Bearer your_jwt_token
   ```

## Testing

The API can be tested using the Postman collection provided in the original assignment. The collection includes tests for most endpoints and demonstrates proper authentication flow.

## License

This project is part of a portfolio assignment for CS 493 at Oregon State University and is available for educational and demonstration purposes.
```
