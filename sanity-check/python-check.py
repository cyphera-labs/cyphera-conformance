#!/usr/bin/env python3
"""Sanity check against independent Python FF1 libraries."""
import json
import sys

# Try mysto (has FF1)
try:
    from mysto import FF1
    HAS_MYSTO = True
except ImportError:
    HAS_MYSTO = False

with open("inputs.json") as f:
    data = json.load(f)

results = []

for case in data["cases"]:
    name = case["name"]
    key = case["key"]
    tweak = case.get("tweak", "")
    radix = case["radix"]
    alpha = case["alphabet"]
    plaintext = case["plaintext"]

    r = {"name": name, "plaintext": plaintext}

    if HAS_MYSTO:
        try:
            ff = FF1(radix, int(len(key) / 2))
            ct = ff.encrypt(key, tweak, plaintext, alphabet=alpha)
            pt = ff.decrypt(key, tweak, ct, alphabet=alpha)
            r["mysto_ciphertext"] = ct
            r["mysto_roundtrip"] = pt == plaintext
            print(f"mysto: {name}: {plaintext} -> {ct} (rt={pt == plaintext})")
        except Exception as e:
            r["mysto_error"] = str(e)
            print(f"mysto: {name}: ERROR {e}")

    if "nist_expected" in case:
        r["nist_expected"] = case["nist_expected"]

    results.append(r)

output = {"library": "mysto 0.8.1 (pypi)", "results": results}
with open("results-python-mysto.json", "w") as f:
    json.dump(output, f, indent=2)
print("\nResults written to results-python-mysto.json")
