#!/usr/bin/env python3
"""Test vector runner for cyphera-python."""
import json
import os
import sys

from cyphera import FF1, FF3, FF31, Cyphera

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
            elif engine == "ff31":
                cipher = FF31(k, t, alpha)
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

    return {**data, "results": results, "runner": "python", "sdk_version": "0.0.1a10"}

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
        policy = c.get("configuration", "test")
        pt = c.get("plaintext", "")
        force_method = c.get("force_method")
        expect_error = c.get("expect_error", False)
        error_must_contain = c.get("error_must_contain")
        input_override = c.get("input_override")

        if not client or isinstance(client, dict):
            r["error"] = client.get("_error", "no config") if isinstance(client, dict) else "no config"
            r["expect_error_satisfied"] = expect_error and r["error"] is not None
            results.append(r)
            continue

        engine_type = data.get("config", {}).get("configurations", {}).get(policy, {}).get("engine", "ff1")
        header_enabled = data.get("config", {}).get("configurations", {}).get(policy, {}).get("header_enabled", True)

        # ─── force_method dispatch (api_contract / error_conditions / schema_fidelity) ───
        if force_method:
            r["error"] = None
            try:
                if force_method == "protect_only":
                    protected = client.protect(pt, policy)
                    r["protected"] = protected
                    if "expected" in c:
                        r["matches_expected"] = protected == c["expected"]
                elif force_method == "protect_only_deterministic":
                    p1 = client.protect(pt, policy)
                    p2 = client.protect(pt, policy)
                    r["protected"] = p1
                    r["deterministic"] = p1 == p2
                elif force_method == "access_with_config":
                    # 2-arg escape hatch: caller passes an explicit configuration name.
                    protected = client.protect(pt, policy)
                    r["protected"] = protected
                    accessed = client.access(protected, configuration_name=policy)
                    r["accessed"] = accessed
                    r["roundtrip"] = accessed == pt
                elif force_method == "access":
                    # 1-arg, header-driven primary path.
                    protected = client.protect(pt, policy)
                    r["protected"] = protected
                    accessed = client.access(protected)
                    r["accessed"] = accessed
                    r["roundtrip"] = accessed == pt
                elif force_method == "access_unknown_input":
                    # Call the 1-arg header-driven access on a value with no known header.
                    client.access(input_override or "ZZZ12345")
                elif force_method == "access_on_mask_output":
                    masked = client.protect(pt, policy)
                    r["protected"] = masked
                    client.access(masked, configuration_name=policy)
                elif force_method == "access_on_hash_output":
                    hashed = client.protect(pt, policy)
                    r["protected"] = hashed
                    client.access(hashed, configuration_name=policy)
                else:
                    r["error"] = f"unknown force_method: {force_method}"
            except Exception as e:
                r["error"] = str(e)

            # Check expectations
            errored = r["error"] is not None
            r["expect_error_satisfied"] = (errored == expect_error)
            if expect_error and error_must_contain and errored:
                r["error_message_satisfied"] = error_must_contain.lower() in r["error"].lower()
            results.append(r)
            continue

        # ─── default dispatch (existing roundtrip pattern) ───
        try:
            protected = client.protect(pt, policy)
            r["protected"] = protected

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
                # Headered configs use the 1-arg primary path. Headerless configs
                # have no header to find, so they require the 2-arg escape hatch.
                if header_enabled:
                    accessed = client.access(protected)
                else:
                    accessed = client.access(protected, configuration_name=policy)
                r["accessed"] = accessed
                r["roundtrip"] = accessed == pt
                r["error"] = None
        except Exception as e:
            r["protected"] = None
            r["roundtrip"] = False
            r["error"] = str(e)
        results.append(r)

    return {**data, "results": results, "runner": "python", "sdk_version": "0.0.1a10"}

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
