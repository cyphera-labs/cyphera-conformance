#!/bin/bash
set -e
cd "$(dirname "$0")"
echo "Building .NET test runner..."
docker build -t cyphera-test-dotnet . -q
echo "Running tests..."
docker run --rm -v "$(cd ../.. && pwd)":/vectors cyphera-test-dotnet
echo "Results written to ../../results/dotnet/"
