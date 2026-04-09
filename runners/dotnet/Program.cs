using System.Text.Json;
using System.Text.Json.Nodes;
using Cyphera;

var inputDir = args.Length > 0 ? args[0] : "inputs";
var outputDir = args.Length > 1 ? args[1] : "results/dotnet";

// Engine tests
var engineIn = Path.Combine(inputDir, "engine");
var engineOut = Path.Combine(outputDir, "engine");
if (Directory.Exists(engineIn))
{
    Directory.CreateDirectory(engineOut);
    foreach (var file in Directory.GetFiles(engineIn, "*.json").OrderBy(f => f))
    {
        var name = Path.GetFileName(file);
        Console.WriteLine($"[engine] {name}");
        var input = JsonNode.Parse(File.ReadAllText(file))!;
        var result = RunEngine(input);
        File.WriteAllText(Path.Combine(engineOut, name), result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

// SDK tests
var sdkIn = Path.Combine(inputDir, "sdk");
var sdkOut = Path.Combine(outputDir, "sdk");
if (Directory.Exists(sdkIn))
{
    Directory.CreateDirectory(sdkOut);
    foreach (var file in Directory.GetFiles(sdkIn, "*.json").OrderBy(f => f))
    {
        var name = Path.GetFileName(file);
        Console.WriteLine($"[sdk] {name}");
        var input = JsonNode.Parse(File.ReadAllText(file))!;
        var result = RunSdk(input);
        File.WriteAllText(Path.Combine(sdkOut, name), result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

Console.WriteLine($"Done. Results in {outputDir}");

// ── Engine runner ──

JsonNode RunEngine(JsonNode input)
{
    var engine = input["engine"]?.GetValue<string>() ?? "ff1";
    var globalAlphabet = input["alphabet"]?.GetValue<string>();
    var globalKey = input["key"]?.GetValue<string>();
    var globalTweak = input["tweak"]?.GetValue<string>();
    var isNist = input["source"] != null;

    var results = new JsonArray();
    foreach (var c in input["cases"]!.AsArray())
    {
        var r = JsonNode.Parse(c!.ToJsonString())!;
        var keyHex = c!["key"]?.GetValue<string>() ?? globalKey ?? "";
        var tweakHex = c["tweak"]?.GetValue<string>() ?? globalTweak ?? "";
        var alpha = c["alphabet"]?.GetValue<string>() ?? globalAlphabet ?? "0123456789";
        var plaintext = c["plaintext"]?.GetValue<string>() ?? "";

        try
        {
            var key = HexToBytes(keyHex);
            var tweak = HexToBytes(tweakHex);
            string encrypted, decrypted;

            if (engine == "ff3")
            {
                var cipher = new FF3(key, tweak, alpha);
                encrypted = cipher.Encrypt(plaintext);
                decrypted = cipher.Decrypt(encrypted);
            }
            else
            {
                var cipher = new FF1(key, tweak, alpha);
                encrypted = cipher.Encrypt(plaintext);
                decrypted = cipher.Decrypt(encrypted);
            }

            r["ciphertext"] = encrypted;
            r["decrypted"] = decrypted;
            r["roundtrip"] = decrypted == plaintext;
            if (isNist && c["expected"] != null)
                r["matches_nist"] = encrypted == c["expected"]!.GetValue<string>();
            r["error"] = null;
        }
        catch (Exception e)
        {
            r["ciphertext"] = null;
            r["decrypted"] = null;
            r["roundtrip"] = false;
            r["error"] = e.Message;
        }

        results.Add(r);
    }

    var output = JsonNode.Parse(input.ToJsonString())!;
    output["results"] = results;
    output["runner"] = "dotnet";
    output["sdk_version"] = "0.0.1-alpha.1";
    return output;
}

// ── SDK runner ──

JsonNode RunSdk(JsonNode input)
{
    Cyphera.Cyphera? client = null;
    string? clientError = null;

    if (input["config"] != null)
    {
        try
        {
            var configDoc = JsonDocument.Parse(input["config"]!.ToJsonString());
            client = Cyphera.Cyphera.FromConfig(configDoc.RootElement);
        }
        catch (Exception e)
        {
            clientError = e.Message;
        }
    }

    var results = new JsonArray();
    foreach (var c in input["cases"]!.AsArray())
    {
        var r = JsonNode.Parse(c!.ToJsonString())!;
        var policy = c!["policy"]?.GetValue<string>() ?? "test";
        var plaintext = c["plaintext"]?.GetValue<string>() ?? "";

        if (client == null)
        {
            r["error"] = clientError ?? "no config provided";
            results.Add(r);
            continue;
        }

        try
        {
            var protected_ = client.Protect(plaintext, policy);
            r["protected"] = protected_;

            var engineType = GetEngine(input, policy);
            var tagEnabled = IsTagEnabled(input, policy);

            if (engineType == "mask")
            {
                if (c["expected"] != null)
                    r["matches_expected"] = protected_ == c["expected"]!.GetValue<string>();
                r["reversible"] = false;
                r["error"] = null;
            }
            else if (engineType == "hash")
            {
                var second = client.Protect(plaintext, policy);
                r["deterministic"] = protected_ == second;
                r["reversible"] = false;
                r["error"] = null;
            }
            else
            {
                if (tagEnabled)
                {
                    var accessed = client.Access(protected_);
                    r["accessed"] = accessed;
                    r["roundtrip"] = accessed == plaintext;
                }
                else
                {
                    var accessed = client.Access(protected_, policy);
                    r["accessed"] = accessed;
                    r["roundtrip"] = accessed == plaintext;
                }

                // Also test explicit access
                var accessedExplicit = client.Access(protected_, policy);
                r["accessed_explicit"] = accessedExplicit;
                r["roundtrip_explicit"] = accessedExplicit == plaintext;
                r["error"] = null;
            }
        }
        catch (Exception e)
        {
            r["protected"] = null;
            r["roundtrip"] = false;
            r["error"] = e.Message;
        }

        results.Add(r);
    }

    var output = JsonNode.Parse(input.ToJsonString())!;
    output["results"] = results;
    output["runner"] = "dotnet";
    output["sdk_version"] = "0.0.1-alpha.1";
    return output;
}

// ── Helpers ──

string GetEngine(JsonNode input, string policyName)
{
    try { return input["config"]!["policies"]![policyName]!["engine"]!.GetValue<string>(); }
    catch { return "ff1"; }
}

bool IsTagEnabled(JsonNode input, string policyName)
{
    try
    {
        var te = input["config"]!["policies"]![policyName]!["tag_enabled"];
        return te == null || te.GetValue<bool>();
    }
    catch { return true; }
}

byte[] HexToBytes(string hex)
{
    if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
    var bytes = new byte[hex.Length / 2];
    for (int i = 0; i < hex.Length; i += 2)
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    return bytes;
}
