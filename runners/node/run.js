"use strict";
const fs = require("fs");
const path = require("path");

const { FF1, FF3, FF31, Cyphera } = require("cyphera");

const inputDir = process.argv[2] || "inputs";
const outputDir = process.argv[3] || "results/node";

// Engine tests
const engineDir = path.join(inputDir, "engine");
const engineOut = path.join(outputDir, "engine");
if (fs.existsSync(engineDir)) {
  fs.mkdirSync(engineOut, { recursive: true });
  for (const file of fs.readdirSync(engineDir).filter(f => f.endsWith(".json"))) {
    console.log(`[engine] ${file}`);
    const input = JSON.parse(fs.readFileSync(path.join(engineDir, file), "utf8"));
    const result = runEngine(input);
    fs.writeFileSync(path.join(engineOut, file), JSON.stringify(result, null, 2));
  }
}

// SDK tests
const sdkDir = path.join(inputDir, "sdk");
const sdkOut = path.join(outputDir, "sdk");
if (fs.existsSync(sdkDir)) {
  fs.mkdirSync(sdkOut, { recursive: true });
  for (const file of fs.readdirSync(sdkDir).filter(f => f.endsWith(".json"))) {
    console.log(`[sdk] ${file}`);
    const input = JSON.parse(fs.readFileSync(path.join(sdkDir, file), "utf8"));
    const result = runSdk(input);
    fs.writeFileSync(path.join(sdkOut, file), JSON.stringify(result, null, 2));
  }
}

console.log(`Done. Results in ${outputDir}`);

function hexToBytes(hex) {
  if (!hex || hex.length === 0) return Buffer.alloc(0);
  return Buffer.from(hex, "hex");
}

function runEngine(input) {
  const engine = input.engine || "ff1";
  const globalAlphabet = input.alphabet || null;
  const globalKey = input.key || null;
  const globalTweak = input.tweak || null;
  const isNist = !!input.source;

  const results = input.cases.map(c => {
    const keyHex = c.key || globalKey || "";
    const tweakHex = c.tweak !== undefined ? c.tweak : globalTweak || "";
    const alpha = c.alphabet || globalAlphabet || "0123456789";
    const plaintext = c.plaintext || "";
    const r = { ...c };

    try {
      const key = hexToBytes(keyHex);
      const tweak = hexToBytes(tweakHex);
      let encrypted, decrypted;

      if (engine === "ff3") {
        const cipher = new FF3(key, tweak, alpha);
        encrypted = cipher.encrypt(plaintext);
        decrypted = cipher.decrypt(encrypted);
      } else if (engine === "ff31") {
        const cipher = new FF31(key, tweak, alpha);
        encrypted = cipher.encrypt(plaintext);
        decrypted = cipher.decrypt(encrypted);
      } else {
        const cipher = new FF1(key, tweak, alpha);
        encrypted = cipher.encrypt(plaintext);
        decrypted = cipher.decrypt(encrypted);
      }

      r.ciphertext = encrypted;
      r.decrypted = decrypted;
      r.roundtrip = decrypted === plaintext;
      if (isNist && c.expected) {
        r.matches_nist = encrypted === c.expected;
      }
      r.error = null;
    } catch (e) {
      r.ciphertext = null;
      r.decrypted = null;
      r.roundtrip = false;
      r.error = e.message;
    }

    return r;
  });

  return { ...input, results, runner: "node", sdk_version: "0.0.1-alpha.6" };
}

function runSdk(input) {
  let client = null;
  if (input.config) {
    try {
      client = new Cyphera(input.config);
    } catch (e) {
      client = { _error: e.message };
    }
  }

  const results = input.cases.map(c => {
    const policy = c.configuration || "test";
    const plaintext = c.plaintext || "";
    const forceMethod = c.force_method;
    const expectError = c.expect_error || false;
    const errorMustContain = c.error_must_contain;
    const inputOverride = c.input_override;
    const r = { ...c };

    if (!client || client._error) {
      r.error = client ? client._error : "no config provided";
      r.expect_error_satisfied = expectError && r.error;
      return r;
    }

    // ─── force_method dispatch ───
    if (forceMethod) {
      r.error = null;
      try {
        if (forceMethod === "protect_only") {
          const p = client.protect(plaintext, policy);
          r.protected = p;
          if (c.expected) r.matches_expected = p === c.expected;
        } else if (forceMethod === "protect_only_deterministic") {
          const p1 = client.protect(plaintext, policy);
          const p2 = client.protect(plaintext, policy);
          r.protected = p1;
          r.deterministic = p1 === p2;
        } else if (forceMethod === "access_with_config") {
          // 2-arg escape hatch: caller passes an explicit configuration name.
          const p = client.protect(plaintext, policy);
          r.protected = p;
          const a = client.access(p, policy);
          r.accessed = a;
          r.roundtrip = a === plaintext;
        } else if (forceMethod === "access") {
          // 1-arg, header-driven primary path.
          const p = client.protect(plaintext, policy);
          r.protected = p;
          const a = client.access(p);
          r.accessed = a;
          r.roundtrip = a === plaintext;
        } else if (forceMethod === "access_unknown_input") {
          client.access(inputOverride || "ZZZ12345");
        } else if (forceMethod === "access_on_mask_output") {
          const m = client.protect(plaintext, policy);
          r.protected = m;
          client.access(m, policy);
        } else if (forceMethod === "access_on_hash_output") {
          const h = client.protect(plaintext, policy);
          r.protected = h;
          client.access(h, policy);
        } else {
          r.error = `unknown force_method: ${forceMethod}`;
        }
      } catch (e) {
        r.error = e.message;
      }

      const errored = r.error !== null && r.error !== undefined;
      r.expect_error_satisfied = errored === expectError;
      if (expectError && errorMustContain && errored) {
        r.error_message_satisfied = r.error.toLowerCase().includes(errorMustContain.toLowerCase());
      }
      return r;
    }

    // ─── default dispatch ───
    try {
      const protected_ = client.protect(plaintext, policy);
      r.protected = protected_;

      const engineType = getEngine(input, policy);

      if (engineType === "mask") {
        if (c.expected) {
          r.matches_expected = protected_ === c.expected;
        }
        r.reversible = false;
        r.error = null;
      } else if (engineType === "hash") {
        const second = client.protect(plaintext, policy);
        r.deterministic = protected_ === second;
        r.reversible = false;
        r.error = null;
      } else {
        // Headered configs use the 1-arg primary path; headerless configs
        // need the 2-arg escape hatch (no header for the SDK to match on).
        const headerEnabled = isHeaderEnabled(input, policy);
        const accessed = headerEnabled
          ? client.access(protected_)
          : client.access(protected_, policy);
        r.accessed = accessed;
        r.roundtrip = accessed === plaintext;
        r.error = null;
      }
    } catch (e) {
      r.protected = null;
      r.roundtrip = false;
      r.error = e.message;
    }

    return r;
  });

  return { ...input, results, runner: "node", sdk_version: "0.0.1-alpha.6" };
}

function getEngine(input, policyName) {
  try {
    return input.config.configurations[policyName].engine || "ff1";
  } catch {
    return "ff1";
  }
}

function isHeaderEnabled(input, policyName) {
  try {
    const te = input.config.configurations[policyName].header_enabled;
    return te !== false;
  } catch {
    return true;
  }
}
