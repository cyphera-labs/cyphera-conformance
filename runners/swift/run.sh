#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Swift test runner..."
docker build -t cyphera-test-swift . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-swift
echo "Results written to ../../results/swift/"
