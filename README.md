# cyphera-conformance

[![Conformance](https://github.com/cyphera-labs/cyphera-conformance/actions/workflows/conformance.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-conformance/actions/workflows/conformance.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Cross-language conformance test suite for Cyphera SDKs. Verifies that all implementations produce identical output for the same inputs.

## What It Tests

**Engine tests** — raw FF1/FF3 encryption against NIST SP 800-38G test vectors:
- 9 NIST FF1 samples (128/192/256-bit keys, digits and alphanumeric alphabets)
- 15 NIST FF3 samples
- Alphanumeric radix-62 tests
- Edge cases and key size variations

**SDK tests** — full protect/access behavior:
- Tagged protect + tag-based access (roundtrip)
- Passthrough preservation (dashes, spaces, unicode)
- Mask engine (last4, first1, full)
- Hash engine (HMAC-SHA256)
- Determinism
- Multibyte and unicode passthroughs

## Runners

Each runner is Dockerized — pulls the published SDK from its registry (not local source):

| Runner | SDK Source | Docker Base |
|--------|-----------|-------------|
| `runners/java/` | `io.cyphera:cyphera` from Maven Central | maven:3.9-eclipse-temurin-11 |
| `runners/rust/` | `cyphera` from crates.io | rust:1.78-slim |
| `runners/node/` | `cyphera` from npm | node:22-slim |
| `runners/python/` | `cyphera` from PyPI | python:3.12-slim |
| `runners/dotnet/` | `Cyphera` from NuGet | mcr.microsoft.com/dotnet/sdk:8.0 |
| `runners/go/` | `cyphera-go` from go pkg | golang:1.22-bookworm |

## Running

### Manually

```bash
# Run a single language
cd runners/python && bash run.sh

# Results written to results/{language}/engine/ and results/{language}/sdk/
```

### Via GitHub Actions

Trigger the conformance workflow manually from the Actions tab. It runs all runners and compares output across languages.

## Cross-Language Verification

All SDKs must produce identical output:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Go:          T01i6J-xF-07pX
.NET:        T01i6J-xF-07pX
PHP:         T01i6J-xF-07pX
```

No single implementation is trusted. Consensus across implementations is the only source of truth.

## Adding a New Language

1. Create `runners/{language}/` with a Dockerfile that installs the published SDK
2. Write a runner script that reads `inputs/engine/*.json` and `inputs/sdk/*.json`
3. Output results in the same JSON format as existing runners
4. Run and verify output matches all other languages

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
