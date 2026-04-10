#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building PHP test runner..."
docker build -t cyphera-test-php . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-php
echo "Results written to ../../results/php/"
