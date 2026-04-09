# Sanity Check Results

## Independent Reference: Rust `fpe` crate v0.6.1

Author: Electric Coin Company (Zcash team)
Source: https://crates.io/crates/fpe

### Results

| Test Case | Input | Reference Output | NIST Expected | Match |
|-----------|-------|-----------------|---------------|-------|
| NIST sample 1 | 0123456789 (r10) | 2433477484 | 2433477484 | YES |
| NIST sample 2 (tweak) | 0123456789 (r10) | 6124200773 | 6124200773 | YES |
| NIST sample 3 (r36) | 0123456789abcdefghi | a9tv40mll9kdu509eum | a9tv40mll9kdu509eum | YES |
| NIST sample 7 (256-bit) | 0123456789 (r10) | 6657667009 | 6657667009 | YES |
| Short r62 (10 chars) | 0123456789 | 9UPVMAoChD | n/a | n/a |
| Medium r62 (50 chars) | abc123def456... | Zi84X5xfK... | n/a | n/a |
| Long r62 (80 chars, 3 blocks) | abc123def456...PQ | DLaKPatPh... | n/a | n/a |
| Very long r62 (124 chars) | abcdefghij...89 | BCeyvEfRX... | n/a | n/a |
| Long r10 (30 digits) | 123456789...0 | 107102517... | n/a | n/a |

All NIST vectors match. All round-trips pass.

## Bug Found and Fixed

During cross-language testing, a bug was found in the `expandS` function across Java, Rust, Node, and Python implementations. All four had the same bug — XORing with the previous encrypted block instead of R (the original PRF output).

This bug only manifests when `d > 32` bytes (3+ AES blocks), which requires inputs of ~75+ characters with radix 62. NIST test vectors use short inputs (max 19 chars) so the bug was never caught by NIST tests.

The `fpe` crate v0.6.1 has the correct implementation (XOR with R), confirming our fix.

## Other Libraries Tested

- `node-fpe` (npm): Not FF1 — uses simple substitution cipher. Not useful.
- `pyffx` (PyPI): Not FF1 — uses Feistel with HMAC. Not useful.
- `ff3` (PyPI): FF3 only, not FF1.
- `mysto` (PyPI): Failed to install correctly.

## Conclusion

Independent verification limited to the Rust `fpe` crate by the Zcash/ECC team. Combined with 9 NIST FF1 test vectors and 15 NIST FF3 test vectors, all passing across our implementations. The expandS fix is confirmed correct.
