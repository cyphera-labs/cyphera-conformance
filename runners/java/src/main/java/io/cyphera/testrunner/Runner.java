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
        out.addProperty("sdk_version", "0.0.1-alpha.1");
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

            String policy = c.has("policy") ? c.get("policy").getAsString() : null;
            String plaintext = c.get("plaintext").getAsString();

            try {
                if (client == null) {
                    throw new IllegalStateException("No config provided for SDK test");
                }

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
                    // Reversible engine — test access
                    boolean tagEnabled = isTagEnabled(input, policy);

                    if (tagEnabled) {
                        // Tag-based access (no policy name needed)
                        String accessed = client.access(protectedVal);
                        r.addProperty("accessed", accessed);
                        r.addProperty("roundtrip", accessed.equals(plaintext));
                    } else {
                        // Explicit policy access (untagged)
                        String accessed = client.access(protectedVal, policy);
                        r.addProperty("accessed", accessed);
                        r.addProperty("roundtrip", accessed.equals(plaintext));
                    }

                    // Always also test explicit policy access
                    String accessedExplicit = client.access(protectedVal, policy);
                    r.addProperty("accessed_explicit", accessedExplicit);
                    r.addProperty("roundtrip_explicit", accessedExplicit.equals(plaintext));

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
        out.addProperty("sdk_version", "0.0.1-alpha.1");
        return out;
    }

    // ── Helpers ──

    static String getEngineFromConfig(JsonObject input, String policyName) {
        try {
            return input.getAsJsonObject("config")
                        .getAsJsonObject("policies")
                        .getAsJsonObject(policyName)
                        .get("engine").getAsString();
        } catch (Exception e) {
            return "ff1";
        }
    }

    static boolean isTagEnabled(JsonObject input, String policyName) {
        try {
            JsonObject policy = input.getAsJsonObject("config")
                                     .getAsJsonObject("policies")
                                     .getAsJsonObject(policyName);
            if (policy.has("tag_enabled")) {
                return policy.get("tag_enabled").getAsBoolean();
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
