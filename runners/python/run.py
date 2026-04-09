#!/usr/bin/env python3
"""Test vector runner for cyphera-python."""
import json
import os
import sys

from cyphera import FF1, FF3, Cyphera

input_dir = sys.argv[1] if len(sys.argv) > 1 else "inputs"
output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/python"

def hex_to_bytes(h):
    return bytes.fromhex(h) if h else b""

def run_engine(data):
    engine = data.get("engine", "ff1")
    global_alpha = data.get("alphabet")
    global_key = data.get("key")
    global_tweak = data.get("tweak")
    is_nist = "source" in data

    results = []
    for c in data["cases"]:
        r = dict(c)
        key = c.get("key", global_key) or ""
        tweak = c.get("tweak", global_tweak) or ""
        alpha = c.get("alphabet", global_alpha) or "0123456789"
        pt = c.get("plaintext", "")

        try:
            k = hex_to_bytes(key)
            t = hex_to_bytes(tweak)
            if engine == "ff3":
                cipher = FF3(k, t, alpha)
            else:
                cipher = FF1(k, t, alpha)
            ct = cipher.encrypt(pt)
            dt = cipher.decrypt(ct)
            r["ciphertext"] = ct
            r["decrypted"] = dt
            r["roundtrip"] = dt == pt
            if is_nist and "expected" in c:
                r["matches_nist"] = ct == c["expected"]
            r["error"] = None
        except Exception as e:
            r["ciphertext"] = None
            r["decrypted"] = None
            r["roundtrip"] = False
            r["error"] = str(e)
        results.append(r)

    return {**data, "results": results, "runner": "python", "sdk_version": "0.0.1a4"}

def run_sdk(data):
    client = None
    if "config" in data:
        try:
            client = Cyphera(data["config"])
        except Exception as e:
            client = {"_error": str(e)}

    results = []
    for c in data["cases"]:
        r = dict(c)
        policy = c.get("policy", "test")
        pt = c.get("plaintext", "")

        if not client or isinstance(client, dict):
            r["error"] = client.get("_error", "no config") if isinstance(client, dict) else "no config"
            results.append(r)
            continue

        try:
            protected = client.protect(pt, policy)
            r["protected"] = protected

            engine_type = data.get("config", {}).get("policies", {}).get(policy, {}).get("engine", "ff1")
            tag_enabled = data.get("config", {}).get("policies", {}).get(policy, {}).get("tag_enabled", True)

            if engine_type == "mask":
                if "expected" in c:
                    r["matches_expected"] = protected == c["expected"]
                r["reversible"] = False
                r["error"] = None
            elif engine_type == "hash":
                second = client.protect(pt, policy)
                r["deterministic"] = protected == second
                r["reversible"] = False
                r["error"] = None
            else:
                if tag_enabled:
                    accessed = client.access(protected)
                else:
                    accessed = client.access(protected, policy)
                r["accessed"] = accessed
                r["roundtrip"] = accessed == pt

                accessed_explicit = client.access(protected, policy)
                r["accessed_explicit"] = accessed_explicit
                r["roundtrip_explicit"] = accessed_explicit == pt
                r["error"] = None
        except Exception as e:
            r["protected"] = None
            r["roundtrip"] = False
            r["error"] = str(e)
        results.append(r)

    return {**data, "results": results, "runner": "python", "sdk_version": "0.0.1a4"}

# Engine tests
engine_dir = os.path.join(input_dir, "engine")
engine_out = os.path.join(output_dir, "engine")
if os.path.exists(engine_dir):
    os.makedirs(engine_out, exist_ok=True)
    for f in sorted(os.listdir(engine_dir)):
        if f.endswith(".json"):
            print(f"[engine] {f}")
            with open(os.path.join(engine_dir, f)) as fh:
                data = json.load(fh)
            result = run_engine(data)
            with open(os.path.join(engine_out, f), "w") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)

# SDK tests
sdk_dir = os.path.join(input_dir, "sdk")
sdk_out = os.path.join(output_dir, "sdk")
if os.path.exists(sdk_dir):
    os.makedirs(sdk_out, exist_ok=True)
    for f in sorted(os.listdir(sdk_dir)):
        if f.endswith(".json"):
            print(f"[sdk] {f}")
            with open(os.path.join(sdk_dir, f)) as fh:
                data = json.load(fh)
            result = run_sdk(data)
            with open(os.path.join(sdk_out, f), "w") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)

print(f"Done. Results in {output_dir}")
