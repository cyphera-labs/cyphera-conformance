"use strict";
const fs = require("fs");
const path = require("path");

const { FF1, FF3, Cyphera } = require("cyphera");

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

  return { ...input, results, runner: "node", sdk_version: "0.0.1-alpha.1" };
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
    const policy = c.policy || "test";
    const plaintext = c.plaintext || "";
    const r = { ...c };

    if (!client || client._error) {
      r.error = client ? client._error : "no config provided";
      return r;
    }

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
        const tagEnabled = isTagEnabled(input, policy);

        if (tagEnabled) {
          const accessed = client.access(protected_);
          r.accessed = accessed;
          r.roundtrip = accessed === plaintext;
        } else {
          const accessed = client.access(protected_, policy);
          r.accessed = accessed;
          r.roundtrip = accessed === plaintext;
        }

        // Also test explicit
        const accessedExplicit = client.access(protected_, policy);
        r.accessed_explicit = accessedExplicit;
        r.roundtrip_explicit = accessedExplicit === plaintext;
        r.error = null;
      }
    } catch (e) {
      r.protected = null;
      r.roundtrip = false;
      r.error = e.message;
    }

    return r;
  });

  return { ...input, results, runner: "node", sdk_version: "0.0.1-alpha.1" };
}

function getEngine(input, policyName) {
  try {
    return input.config.policies[policyName].engine || "ff1";
  } catch {
    return "ff1";
  }
}

function isTagEnabled(input, policyName) {
  try {
    const te = input.config.policies[policyName].tag_enabled;
    return te !== false;
  } catch {
    return true;
  }
}
