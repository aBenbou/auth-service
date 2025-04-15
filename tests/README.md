# Authentication API Tests

This directory contains comprehensive tests for the Authentication and Authorization API.

## Test Structure

The tests are organized into the following directories:

- `test_models/` - Tests for database models and their relationships
- `test_services/` - Tests for service layer functions
- `test_api/` - Tests for API endpoints

## Running Tests

To run the tests, use the following command from the project root:

```bash
pytest
```

Or run specific test files:

```bash
pytest tests/test_models/test_user.py
```

You can also run tests with coverage report:

```bash
pytest --cov=app --cov-report=term-missing
```

## Test Configuration

The test configuration is defined in `conftest.py` and includes:

- In-memory SQLite database for fast testing
- Mocked Redis server using `fakeredis`
- Mocked email service
- Test fixtures for common objects (users, services, tokens, etc.)

## Writing Tests

When writing new tests:

1. Use the appropriate directory based on what you're testing
2. Use existing fixtures from `conftest.py` where possible
3. Follow the naming convention: `test_feature_scenario`
4. Keep tests focused on a single functionality
5. Make assertions that verify both the response and the database state

## Test Coverage

Tests should cover:

- Happy path (successful operations)
- Error conditions
- Edge cases
- Authorization requirements

## Database Handling

Tests use a temporary in-memory SQLite database that is created for each test and discarded afterward. The database is configured with the same schema as the production database but doesn't persist between test runs.

## Mocked Dependencies

The following dependencies are mocked for testing:

- Redis server (using `fakeredis`)
- Email sending
- OAuth providers

## Running in CI

These tests are configured to run in CI environments. The tests don't depend on any external services, so they should run reliably in any environment. 