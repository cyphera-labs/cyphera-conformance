#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Python test runner..."
docker build -t cyphera-test-python . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-python
echo "Results written to ../../results/python/"
