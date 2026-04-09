#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building Rust test runner..."
docker build -t cyphera-test-rust . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-rust
echo "Results written to ../../results/rust/"
