#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Java test runner..."
docker build -t cyphera-test-java . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-java
echo "Results written to ../../results/java/"
