#!/bin/bash
set -e

# Build the test Docker image
echo "Building test Docker image..."
docker build -t auth-api-tests -f Dockerfile.test .

# Run the tests
echo "Running tests..."
docker run --rm auth-api-tests

echo "Tests completed." 