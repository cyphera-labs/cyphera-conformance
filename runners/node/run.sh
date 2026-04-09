#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Node test runner..."
docker build -t cyphera-test-node . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-node
echo "Results written to ../../results/node/"
