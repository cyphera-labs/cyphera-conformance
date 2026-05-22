#!/usr/bin/env python3
"""
Cross-language conformance comparison.

Reads results/<runner>/sdk/*.json for every runner, walks each case in
each fixture, and reports cases where the SDKs disagree on any of:

  - `protected` (the bytes/string returned by protect())
  - `accessed` (the bytes/string returned by access())
  - `roundtrip` (whether protect → access returned the original)
  - `expect_error_satisfied` (whether the case errored as expected)
  - `error_message_satisfied` (whether the error message matched)
  - `deterministic` (whether protect is deterministic for the configured engine)
  - `matches_expected` (whether protect output matches a hardcoded expected value)

Exit code: 0 if no divergences, 1 if any.

Usage:
  python3 compare.py [results_dir]    # default: ./results

Output:
  - Summary table: per-runner case counts (pass / fail / divergent)
  - Divergence report: per-fixture, per-case, what each SDK reported
"""
import json
import os
import sys
from collections import defaultdict

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "results"

# Fields to compare across SDKs. Each entry is (field_name, kind).
#   kind: 'value' = strict equality; 'bool' = boolean equality.
COMPARE_FIELDS = [
    ("protected", "value"),
    ("accessed", "value"),
    ("roundtrip", "bool"),
    ("roundtrip_explicit", "bool"),
    ("expect_error_satisfied", "bool"),
    ("error_message_satisfied", "bool"),
    ("deterministic", "bool"),
    ("matches_expected", "bool"),
    ("matches_nist", "bool"),
]

def case_id(case):
    """A stable identifier for a case within its fixture."""
    parts = []
    if "configuration" in case: parts.append(f"cfg={case['configuration']}")
    if "force_method" in case: parts.append(f"method={case['force_method']}")
    if "plaintext" in case:
        pt = case["plaintext"]
        if len(pt) > 24: pt = pt[:20] + "..."
        parts.append(f"pt={pt!r}")
    if "note" in case and not parts:
        parts.append(f"note={case['note'][:40]}")
    return " | ".join(parts) if parts else "<unidentified>"

def load_runner_results(runner_dir):
    """Read all sdk/*.json from a runner's results dir. Returns {fixture: data}."""
    sdk_dir = os.path.join(runner_dir, "sdk")
    if not os.path.isdir(sdk_dir):
        return {}
    out = {}
    for fname in sorted(os.listdir(sdk_dir)):
        if not fname.endswith(".json"): continue
        with open(os.path.join(sdk_dir, fname)) as f:
            try:
                out[fname] = json.load(f)
            except Exception as e:
                out[fname] = {"_error": f"failed to load: {e}"}
    return out

def main():
    if not os.path.isdir(RESULTS_DIR):
        print(f"results directory not found: {RESULTS_DIR}", file=sys.stderr)
        sys.exit(2)

    runners = sorted([d for d in os.listdir(RESULTS_DIR)
                      if os.path.isdir(os.path.join(RESULTS_DIR, d))])
    if not runners:
        print(f"no runners found under {RESULTS_DIR}", file=sys.stderr)
        sys.exit(2)

    # Load all
    all_results = {r: load_runner_results(os.path.join(RESULTS_DIR, r)) for r in runners}

    # Collect every fixture that any runner produced
    fixtures = sorted(set(f for r in runners for f in all_results[r].keys()))

    # ── Per-runner summary ──
    print("=" * 78)
    print(f"{'Runner':<12} {'Fixtures':>8} {'Cases':>8} {'Errors':>8} {'Missing':>10}")
    print("-" * 78)
    for r in runners:
        n_fixtures = len(all_results[r])
        n_cases = sum(len(d.get("results", [])) for d in all_results[r].values())
        n_errors = sum(1 for d in all_results[r].values() for c in d.get("results", []) if c.get("error"))
        n_missing = len(fixtures) - n_fixtures
        print(f"{r:<12} {n_fixtures:>8} {n_cases:>8} {n_errors:>8} {n_missing:>10}")
    print()

    # ── Per-fixture divergence detection ──
    total_divergences = 0
    total_cases = 0

    for fixture in fixtures:
        # Map case_index -> {runner -> case_result}
        per_case = defaultdict(dict)
        max_n = 0
        for r in runners:
            d = all_results[r].get(fixture)
            if not d or "results" not in d: continue
            results = d["results"]
            max_n = max(max_n, len(results))
            for i, c in enumerate(results):
                per_case[i][r] = c

        if max_n == 0: continue

        # Report per fixture
        diverged_in_fixture = []
        for i in range(max_n):
            results_for_case = per_case[i]
            # Sample any case for the identifier (assume all SDKs see same input case)
            sample = next(iter(results_for_case.values()))
            cid = case_id(sample)
            total_cases += 1

            for field, _kind in COMPARE_FIELDS:
                vals = {}
                for r, c in results_for_case.items():
                    if field in c:
                        vals[r] = c[field]
                if len(vals) <= 1: continue
                # Strict equality across all SDKs
                unique = set()
                for v in vals.values():
                    try: unique.add(v if isinstance(v, (bool, int, str, type(None))) else json.dumps(v, sort_keys=True))
                    except: unique.add(repr(v))
                if len(unique) > 1:
                    diverged_in_fixture.append((i, cid, field, vals))

        if diverged_in_fixture:
            total_divergences += len(diverged_in_fixture)
            print(f"=== DIVERGENCE in {fixture} ({len(diverged_in_fixture)} field-disagreements) ===")
            for i, cid, field, vals in diverged_in_fixture:
                print(f"  [case {i}] {cid}")
                print(f"     field '{field}':")
                # Group runners by value for readability
                groups = defaultdict(list)
                for r, v in vals.items():
                    groups[json.dumps(v) if not isinstance(v, (str, type(None))) else repr(v)].append(r)
                for vstr, rs in groups.items():
                    print(f"       {','.join(sorted(rs))}: {vstr}")
            print()

    print("=" * 78)
    print(f"Total cases compared: {total_cases}")
    print(f"Field-disagreements:  {total_divergences}")
    print("=" * 78)
    sys.exit(1 if total_divergences > 0 else 0)

if __name__ == "__main__":
    main()
