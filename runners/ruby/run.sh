#!/bin/bash
set -e
cd "$(dirname "$0")"
docker build -t cyphera-runner-ruby -q .
docker run --rm \
  -v "$(realpath ../../inputs):/vectors/inputs:ro" \
  -v "$(realpath ../../results):/vectors/results" \
  cyphera-runner-ruby ruby /app/run.rb /vectors/inputs /vectors/results/ruby
