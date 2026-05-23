package io.cyphera.testrunner;

import com.google.gson.*;
import io.cyphera.Cyphera;
import io.cyphera.engine.ff1.FF1;
import io.cyphera.engine.ff3.FF3;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Test vector runner for cyphera-java.
 *
 * Reads input JSON files from inputs/engine/ and inputs/sdk/
 * Writes result JSON files to results/java/engine/ and results/java/sdk/
 */
public class Runner {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public static void main(String[] args) throws Exception {
        Path baseInput = Paths.get(args.length > 0 ? args[0] : "inputs");
        Path baseOutput = Paths.get(args.length > 1 ? args[1] : "results/java");

        // Engine tests
        Path engineIn = baseInput.resolve("engine");
        Path engineOut = baseOutput.resolve("engine");
        if (engineIn.toFile().exists()) {
            Files.createDirectories(engineOut);
            for (File f : engineIn.toFile().listFiles((d, n) -> n.endsWith(".json"))) {
                System.out.println("[engine] " + f.getName());
                JsonObject input = readJson(f);
                JsonObject result = runEngine(input);
                writeJson(engineOut.resolve(f.getName()), result);
            }
        }

        // SDK tests
        Path sdkIn = baseInput.resolve("sdk");
        Path sdkOut = baseOutput.resolve("sdk");
        if (sdkIn.toFile().exists()) {
            Files.createDirectories(sdkOut);
            for (File f : sdkIn.toFile().listFiles((d, n) -> n.endsWith(".json"))) {
                System.out.println("[sdk] " + f.getName());
                JsonObject input = readJson(f);
                JsonObject result = runSdk(input);
                writeJson(sdkOut.resolve(f.getName()), result);
            }
        }

        System.out.println("Done. Results in " + baseOutput.toAbsolutePath());
    }

    // ── Engine tests (raw FF1/FF3, no passthrough, no tags) ──

    static JsonObject runEngine(JsonObject input) {
        String engine = input.has("engine") ? input.get("engine").getAsString() : "ff1";
        String globalAlphabet = input.has("alphabet") ? input.get("alphabet").getAsString() : null;
        String globalKey = input.has("key") ? input.get("key").getAsString() : null;
        String globalTweak = input.has("tweak") ? input.get("tweak").getAsString() : null;
        boolean isNist = input.has("source");

        JsonArray cases = input.getAsJsonArray("cases");
        JsonArray results = new JsonArray();

        for (JsonElement el : cases) {
            JsonObject c = el.getAsJsonObject();
            JsonObject r = c.deepCopy();

            String key = c.has("key") ? c.get("key").getAsString() : globalKey;
            String tweak = c.has("tweak") ? c.get("tweak").getAsString() : globalTweak;
            String alpha = c.has("alphabet") ? c.get("alphabet").getAsString() : globalAlphabet;
            String plaintext = c.get("plaintext").getAsString();

            try {
                String encrypted;
                String decrypted;

                if ("ff3".equals(engine)) {
                    byte[] tweakBytes = hexToBytes(tweak);
                    FF3 ff3 = new FF3(hexToBytes(key), tweakBytes, alpha);
                    encrypted = ff3.encrypt(plaintext);
                    decrypted = ff3.decrypt(encrypted);
                } else if ("ff31".equals(engine)) {
                    io.cyphera.engine.ff3.FF31 ff31 =
                        new io.cyphera.engine.ff3.FF31(hexToBytes(key), hexToBytes(tweak), alpha);
                    encrypted = ff31.encrypt(plaintext);
                    decrypted = ff31.decrypt(encrypted);
                } else {
                    byte[] tweakBytes = (tweak == null || tweak.isEmpty()) ? new byte[0] : hexToBytes(tweak);
                    FF1 ff1 = new FF1(hexToBytes(key), tweakBytes, alpha);
                    encrypted = ff1.encrypt(plaintext);
                    decrypted = ff1.decrypt(encrypted);
                }

                r.addProperty("ciphertext", encrypted);
                r.addProperty("decrypted", decrypted);
                r.addProperty("roundtrip", decrypted.equals(plaintext));

                if (isNist && c.has("expected")) {
                    r.addProperty("matches_nist", encrypted.equals(c.get("expected").getAsString()));
                }

                r.addProperty("error", (String) null);
            } catch (Exception e) {
                r.addProperty("ciphertext", (String) null);
                r.addProperty("decrypted", (String) null);
                r.addProperty("roundtrip", false);
                r.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            }

            results.add(r);
        }

        JsonObject out = input.deepCopy();
        out.add("results", results);
        out.addProperty("runner", "java");
        out.addProperty("sdk_version", "0.0.1-alpha.8");
        return out;
    }

    // ── SDK tests (protect/access with policies, tags, passthroughs) ──

    @SuppressWarnings("unchecked")
    static JsonObject runSdk(JsonObject input) {
        JsonArray cases = input.getAsJsonArray("cases");
        JsonArray results = new JsonArray();

        Cyphera client = null;
        if (input.has("config")) {
            Map<String, Object> config = GSON.fromJson(input.get("config"), Map.class);
            client = Cyphera.fromMap(config);
        }

        for (JsonElement el : cases) {
            JsonObject c = el.getAsJsonObject();
            JsonObject r = c.deepCopy();

            String policy = c.has("configuration") ? c.get("configuration").getAsString() : null;
            String plaintext = c.has("plaintext") ? c.get("plaintext").getAsString() : "";
            String forceMethod = c.has("force_method") ? c.get("force_method").getAsString() : null;
            boolean expectError = c.has("expect_error") && c.get("expect_error").getAsBoolean();
            String errorMustContain = c.has("error_must_contain") ? c.get("error_must_contain").getAsString() : null;
            String inputOverride = c.has("input_override") ? c.get("input_override").getAsString() : null;

            if (client == null) {
                r.addProperty("error", "No config provided for SDK test");
                r.addProperty("expect_error_satisfied", expectError);
                results.add(r);
                continue;
            }

            // ─── force_method dispatch ───
            if (forceMethod != null) {
                String errMsg = null;
                try {
                    switch (forceMethod) {
                        case "protect_only": {
                            String p = client.protect(plaintext, policy);
                            r.addProperty("protected", p);
                            if (c.has("expected")) r.addProperty("matches_expected", p.equals(c.get("expected").getAsString()));
                            break;
                        }
                        case "protect_only_deterministic": {
                            String p1 = client.protect(plaintext, policy);
                            String p2 = client.protect(plaintext, policy);
                            r.addProperty("protected", p1);
                            r.addProperty("deterministic", p1.equals(p2));
                            break;
                        }
                        case "access_with_config": {
                            // 2-arg escape hatch: caller passes an explicit configuration name.
                            String p = client.protect(plaintext, policy);
                            r.addProperty("protected", p);
                            String a = client.access(p, policy);
                            r.addProperty("accessed", a);
                            r.addProperty("roundtrip", a.equals(plaintext));
                            break;
                        }
                        case "access": {
                            // 1-arg, header-driven primary path.
                            String p = client.protect(plaintext, policy);
                            r.addProperty("protected", p);
                            String a = client.access(p);
                            r.addProperty("accessed", a);
                            r.addProperty("roundtrip", a.equals(plaintext));
                            break;
                        }
                        case "access_unknown_input": {
                            client.access(inputOverride != null ? inputOverride : "ZZZ12345");
                            break;
                        }
                        case "access_on_mask_output": {
                            String m = client.protect(plaintext, policy);
                            r.addProperty("protected", m);
                            client.access(m, policy);
                            break;
                        }
                        case "access_on_hash_output": {
                            String h = client.protect(plaintext, policy);
                            r.addProperty("protected", h);
                            client.access(h, policy);
                            break;
                        }
                        default:
                            errMsg = "unknown force_method: " + forceMethod;
                    }
                } catch (Exception e) {
                    errMsg = e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                r.addProperty("error", errMsg);
                boolean errored = errMsg != null;
                r.addProperty("expect_error_satisfied", errored == expectError);
                if (expectError && errorMustContain != null && errored) {
                    r.addProperty("error_message_satisfied",
                        errMsg.toLowerCase().contains(errorMustContain.toLowerCase()));
                }
                results.add(r);
                continue;
            }

            // ─── default dispatch ───
            try {
                String protectedVal = client.protect(plaintext, policy);
                r.addProperty("protected", protectedVal);

                String engineType = getEngineFromConfig(input, policy);

                if ("mask".equals(engineType)) {
                    if (c.has("expected")) {
                        r.addProperty("matches_expected", protectedVal.equals(c.get("expected").getAsString()));
                    }
                    r.addProperty("reversible", false);
                    r.addProperty("error", (String) null);

                } else if ("hash".equals(engineType)) {
                    String second = client.protect(plaintext, policy);
                    r.addProperty("deterministic", protectedVal.equals(second));
                    r.addProperty("reversible", false);
                    r.addProperty("error", (String) null);

                } else {
                    // Headered configs use the 1-arg primary path; headerless configs
                    // need the 2-arg escape hatch (no header for the SDK to match on).
                    boolean headerEnabled = isHeaderEnabled(input, policy);
                    String accessed = headerEnabled
                        ? client.access(protectedVal)
                        : client.access(protectedVal, policy);
                    r.addProperty("accessed", accessed);
                    r.addProperty("roundtrip", accessed.equals(plaintext));
                    r.addProperty("error", (String) null);
                }
            } catch (Exception e) {
                r.addProperty("protected", (String) null);
                r.addProperty("roundtrip", false);
                r.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            }

            results.add(r);
        }

        JsonObject out = input.deepCopy();
        out.add("results", results);
        out.addProperty("runner", "java");
        out.addProperty("sdk_version", "0.0.1-alpha.8");
        return out;
    }

    // ── Helpers ──

    static String getEngineFromConfig(JsonObject input, String policyName) {
        try {
            return input.getAsJsonObject("config")
                        .getAsJsonObject("configurations")
                        .getAsJsonObject(policyName)
                        .get("engine").getAsString();
        } catch (Exception e) {
            return "ff1";
        }
    }

    static boolean isHeaderEnabled(JsonObject input, String policyName) {
        try {
            JsonObject policy = input.getAsJsonObject("config")
                                     .getAsJsonObject("configurations")
                                     .getAsJsonObject(policyName);
            if (policy.has("header_enabled")) {
                return policy.get("header_enabled").getAsBoolean();
            }
            return true; // default
        } catch (Exception e) {
            return true;
        }
    }

    static JsonObject readJson(File f) throws IOException {
        return GSON.fromJson(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8), JsonObject.class);
    }

    static void writeJson(Path path, JsonObject obj) throws IOException {
        Files.write(path, GSON.toJson(obj).getBytes(StandardCharsets.UTF_8));
    }

    static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2)
            r[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return r;
    }
}
