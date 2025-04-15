# Authentication and Authorization Microservice

A comprehensive authentication and authorization server built with Flask, designed to be part of a microservice architecture. This service provides centralized user management, authentication, and authorization for other microservices.


## System Architecture

This authentication service functions as a central identity provider within a microservice architecture:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Microservice 1 │     │  Microservice 2 │     │  Microservice 3 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │                       │                       │
         │                       ▼                       │
         │            ┌─────────────────────┐           │
         └───────────►  Auth Microservice   ◄───────────┘
                      └──────────┬──────────┘
                                 │
                      ┌──────────┴──────────┐
                      │                     │
                 ┌────▼─────┐         ┌─────▼────┐
                 │ Database │         │  Redis   │
                 └──────────┘         └──────────┘
```

### Components

- **Flask API**: Core application with RESTful endpoints
- **PostgreSQL**: Primary database for user, role, and permission storage
- **Redis**: Session tracking and rate limiting
- **JWT**: Authentication tokens for users and services
- **OAuth Integration**: Authentication with Google, Microsoft, and Discord

## Features

### Authentication
- User registration with email verification
- Login/logout with session tracking
- Password reset functionality
- OAuth 2.0 integration with:
  - Google
  - Microsoft
  - Discord
- JWT-based authentication with access and refresh tokens
- Session management (view, delete, limit concurrent sessions)

### Authorization
- Role-based access control (RBAC)
- Permission-based authorization
- Service-specific roles and permissions
- User-service-role assignments

### Microservice Integration
- Application token generation and validation for service-to-service communication
- Service registration and management
- API endpoints for token validation

### Security
- Password hashing with bcrypt
- Email verification
- Rate limiting (via Redis)
- Session tracking and management
- Token expiration and refresh

### Monitoring
- Active session tracking
- Token usage statistics

## Technology Stack

- **Flask**: Web framework
- **SQLAlchemy**: ORM for database interactions
- **PostgreSQL**: Primary database
- **Redis**: Session storage and rate limiting
- **JWT**: Authentication tokens
- **Docker**: Containerization
- **Authlib**: OAuth implementation

## Installation and Setup

### Prerequisites

- Docker and Docker Compose
- SMTP server for email functionality (or use a service like Mailgun, SendGrid)
- OAuth credentials (for Google, Microsoft, Discord) if using those features

### Local Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd auth_api
   ```

2. Copy environment example and configure:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Start services with Docker Compose:
   ```bash
   docker-compose up -d
   ```

4. Access the API at http://localhost:5000

### Running with Docker

The project includes Docker configuration for easy deployment:

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

## Testing

### Running Tests Locally

The project includes comprehensive tests for all components:

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage report
pytest --cov=app --cov-report=term-missing
```

### Using Docker for Testing

We provide a dedicated Dockerfile for testing:

```bash
# Run tests using Docker
./run_tests.sh
```

Or manually:

```bash
docker build -t auth-api-tests -f Dockerfile.test .
docker run --rm auth-api-tests
```

## API Documentation

### Authentication Endpoints

- `POST /api/auth/register`: Register a new user
- `GET /api/auth/verify-email/<token>`: Verify email address
- `POST /api/auth/login`: Authenticate and get tokens
- `POST /api/auth/logout`: Invalidate current session
- `POST /api/auth/refresh`: Get new access token using refresh token
- `GET /api/auth/me`: Get current user profile
- `POST /api/auth/change-password`: Change password (requires current password)

### Password Management

- `POST /api/password/forgot`: Request password reset
- `POST /api/password/reset`: Reset password with token

### OAuth Endpoints

- `GET /api/oauth/google`: Initiate Google OAuth flow
- `GET /api/oauth/google/callback`: Google OAuth callback
- `GET /api/oauth/microsoft`: Initiate Microsoft OAuth flow
- `GET /api/oauth/microsoft/callback`: Microsoft OAuth callback
- `GET /api/oauth/discord`: Initiate Discord OAuth flow
- `GET /api/oauth/discord/callback`: Discord OAuth callback

### Session Management

- `GET /api/auth/sessions`: List user's active sessions
- `DELETE /api/auth/sessions/<session_id>`: Delete specific session
- `DELETE /api/auth/sessions`: Delete all sessions except current
- `GET /api/auth/sessions/stats`: Get session statistics

### Token Management

- `POST /api/tokens/`: Create new application token
- `GET /api/tokens/service/<service_id>`: Get tokens for a service
- `POST /api/tokens/<token_id>/revoke`: Revoke a token
- `DELETE /api/tokens/<token_id>`: Delete a token
- `GET /api/tokens/validate`: Validate an application token

### Role and Permission Management

- `GET /api/roles/user/<user_id>/service/<service_id>`: Get user roles for service
- `POST /api/roles/user/<user_id>/service/<service_id>/role/<role_id>`: Assign role
- `DELETE /api/roles/user/<user_id>/service/<service_id>/role/<role_id>`: Remove role
- `POST /api/roles/service/<service_id>`: Create new role
- `PUT /api/roles/<role_id>`: Update role
- `DELETE /api/roles/<role_id>`: Delete role
- `GET /api/roles/service/<service_id>`: Get all roles for service
- `GET /api/roles/permissions`: Get all permissions

### Service Management

- `GET /api/roles/services`: Get all services
- `GET /api/roles/services/user`: Get services for current user
- `POST /api/roles/services`: Create new service
- `PUT /api/roles/services/<service_id>`: Update service
- `DELETE /api/roles/services/<service_id>`: Delete service

## Configuration

The `.env` file contains all configuration options. Key settings include:

### Core Configuration
```
# Flask configuration
FLASK_APP=app
FLASK_ENV=development
SECRET_KEY=your_secret_key_here
DEBUG=True

# Database configuration
DATABASE_URI=postgresql://postgres:postgres@db:5432/auth_db
```

### Authentication Configuration
```
# JWT configuration
JWT_SECRET_KEY=your_jwt_secret_key_here
JWT_ACCESS_TOKEN_EXPIRES=3600  # 1 hour
JWT_REFRESH_TOKEN_EXPIRES=2592000  # 30 days

# OAuth configuration
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
# And similar for Microsoft and Discord
```

### Session and Email Configuration
```
# Redis configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Mail configuration
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
```

## Development Guidelines

### Project Structure

```
auth-service/
├── app/                    # Application package
│   ├── api/                # API endpoints
│   ├── models/             # Database models
│   ├── services/           # Business logic
│   └── utils/              # Utility functions
├── tests/                  # Test suite
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Main Dockerfile
├── Dockerfile.test         # Dockerfile for testing
└── run.py                  # Application entry point
```

### Adding New Features

1. Create/update models in `app/models/`
2. Implement business logic in `app/services/`
3. Create API endpoints in `app/api/`
4. Add tests in `tests/`

## Next Steps for Improvement

1. **Enhanced Security**:
   - Implement IP-based rate limiting
   - Add CAPTCHA for registration and login attempts
   - Add two-factor authentication (2FA)
   - Implement device fingerprinting for suspicious login detection

2. **Scalability Improvements**:
   - Add horizontal scaling capabilities with load balancing
   - Implement caching for frequently accessed data
   - Optimize database queries and indexes

3. **Monitoring and Logging**:
   - Add comprehensive logging with ELK stack integration
   - Implement health check endpoints
   - Create dashboards for monitoring system health
   - Add alerting for suspicious activities

4. **Additional Features**:
   - Support for more OAuth providers (Apple, Facebook, GitHub)
   - User profile management
   - Account merging for users with multiple OAuth identities
   - Organization/team management with hierarchical permissions
   - API key management for developers

5. **Developer Experience**:
   - Create SDK libraries for common languages
   - Improve API documentation with OpenAPI/Swagger
   - Add webhook support for authentication events
   - Create admin dashboard UI


## Database Migrations

This project includes a custom database migration system that allows you to manage your database schema changes in a controlled way. Migrations are stored as SQL files in the `migrations` directory, with separate subdirectories for `up` (applying changes) and `down` (reverting changes) migrations.

### Migration Commands

You can use the following commands to manage migrations:

```bash
# Create a new migration
./run.py migrate create "migration_name"

# Apply all pending migrations
./run.py migrate up

# Apply a specific number of pending migrations
./run.py migrate up --steps 1

# Revert the most recent migration
./run.py migrate down --steps 1

# Revert all migrations
./run.py migrate down
```

### Migration Files

Migration files are stored in the `migrations` directory with the following structure:

```
migrations/
  ├── up/
  │   ├── 20240309000001-create-users-table.sql
  │   ├── 20240309000002-create-services-table.sql
  │   └── ...
  └── down/
      ├── 20240309000001-create-users-table.sql
      ├── 20240309000002-create-services-table.sql
      └── ...
```

Each migration file is prefixed with a timestamp and contains SQL statements to apply or revert the migration. The migration system keeps track of applied migrations in a `migrations` table in your database.

### Creating Custom Migrations

When you create a new migration, two files are generated:
1. An "up" migration file in `migrations/up/` for applying changes
2. A "down" migration file in `migrations/down/` for reverting changes

Edit these files to include the SQL statements needed for your schema changes. 