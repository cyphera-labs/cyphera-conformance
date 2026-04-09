#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Go test runner..."
docker build -t cyphera-test-go . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-go
echo "Results written to ../../results/go/"
