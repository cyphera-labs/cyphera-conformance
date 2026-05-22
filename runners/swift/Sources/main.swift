import Foundation
import Cyphera

let inputDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "inputs"
let outputDir = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "results/swift"

let fm = FileManager.default

// Engine tests
let engineDir = "\(inputDir)/engine"
let engineOut = "\(outputDir)/engine"
if fm.fileExists(atPath: engineDir) {
    try fm.createDirectory(atPath: engineOut, withIntermediateDirectories: true)
    for file in try fm.contentsOfDirectory(atPath: engineDir).filter({ $0.hasSuffix(".json") }).sorted() {
        print("[engine] \(file)")
        let data = try Data(contentsOf: URL(fileURLWithPath: "\(engineDir)/\(file)"))
        let input = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let result = runEngine(input)
        let out = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
        try out.write(to: URL(fileURLWithPath: "\(engineOut)/\(file)"))
    }
}

// SDK tests
let sdkDir = "\(inputDir)/sdk"
let sdkOut = "\(outputDir)/sdk"
if fm.fileExists(atPath: sdkDir) {
    try fm.createDirectory(atPath: sdkOut, withIntermediateDirectories: true)
    for file in try fm.contentsOfDirectory(atPath: sdkDir).filter({ $0.hasSuffix(".json") }).sorted() {
        print("[sdk] \(file)")
        let data = try Data(contentsOf: URL(fileURLWithPath: "\(sdkDir)/\(file)"))
        let input = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let result = runSdk(input)
        let out = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
        try out.write(to: URL(fileURLWithPath: "\(sdkOut)/\(file)"))
    }
}

print("Done. Results in \(outputDir)")

func hexToBytes(_ hex: String) -> Data {
    if hex.isEmpty { return Data() }
    let len = hex.count / 2
    var data = Data(capacity: len)
    var i = hex.startIndex
    for _ in 0..<len {
        let j = hex.index(i, offsetBy: 2)
        if let num = UInt8(hex[i..<j], radix: 16) {
            data.append(num)
        }
        i = j
    }
    return data
}

func runEngine(_ input: [String: Any]) -> [String: Any] {
    let engine = input["engine"] as? String ?? "ff1"
    let globalAlphabet = input["alphabet"] as? String
    let globalKey = input["key"] as? String
    let globalTweak = input["tweak"] as? String
    let isNist = input["source"] != nil
    let cases = input["cases"] as? [[String: Any]] ?? []

    let results: [[String: Any]] = cases.map { c in
        let keyHex = c["key"] as? String ?? globalKey ?? ""
        let tweakHex: String
        if let t = c["tweak"] as? String {
            tweakHex = t
        } else {
            tweakHex = globalTweak ?? ""
        }
        let alpha = c["alphabet"] as? String ?? globalAlphabet ?? "0123456789"
        let plaintext = c["plaintext"] as? String ?? ""
        var r = c

        do {
            let key = hexToBytes(keyHex)
            let tweak = hexToBytes(tweakHex)
            let encrypted: String
            let decrypted: String

            if engine == "ff3" {
                let cipher = try FF3(key: key, tweak: tweak, alphabet: alpha)
                encrypted = try cipher.encrypt(plaintext)
                decrypted = try cipher.decrypt(encrypted)
            } else if engine == "ff31" {
                let cipher = try FF31(key: key, tweak: tweak, alphabet: alpha)
                encrypted = try cipher.encrypt(plaintext)
                decrypted = try cipher.decrypt(encrypted)
            } else {
                let cipher = try FF1(key: key, tweak: tweak, alphabet: alpha)
                encrypted = try cipher.encrypt(plaintext)
                decrypted = try cipher.decrypt(encrypted)
            }

            r["ciphertext"] = encrypted
            r["decrypted"] = decrypted
            r["roundtrip"] = decrypted == plaintext
            if isNist, let expected = c["expected"] as? String {
                r["matches_nist"] = encrypted == expected
            }
            r["error"] = NSNull()
        } catch {
            r["ciphertext"] = NSNull()
            r["decrypted"] = NSNull()
            r["roundtrip"] = false
            r["error"] = error.localizedDescription
        }

        return r
    }

    var out = input
    out["results"] = results
    out["runner"] = "swift"
    out["sdk_version"] = "0.0.1-alpha.5"
    return out
}

func runSdk(_ input: [String: Any]) -> [String: Any] {
    let config = input["config"] as? [String: Any]
    let cases = input["cases"] as? [[String: Any]] ?? []

    var client: Cyphera? = nil
    var clientError: String? = nil

    if let config = config {
        do {
            client = try Cyphera(config: config)
        } catch {
            clientError = error.localizedDescription
        }
    }

    let results: [[String: Any]] = cases.map { c in
        let policy = c["configuration"] as? String ?? "test"
        let plaintext = c["plaintext"] as? String ?? ""
        let forceMethod = c["force_method"] as? String
        let expectError = c["expect_error"] as? Bool ?? false
        let errorMustContain = c["error_must_contain"] as? String
        let inputOverride = c["input_override"] as? String
        var r = c

        guard let client = client, clientError == nil else {
            r["error"] = clientError ?? "no config provided"
            r["expect_error_satisfied"] = expectError
            return r
        }

        // ─── force_method dispatch ───
        if let method = forceMethod {
            var errMsg: String? = nil
            do {
                switch method {
                case "protect_only":
                    let p = try client.protect(plaintext, configuration: policy)
                    r["protected"] = p
                    if let expected = c["expected"] as? String { r["matches_expected"] = p == expected }
                case "protect_only_deterministic":
                    let p1 = try client.protect(plaintext, configuration: policy)
                    let p2 = try client.protect(plaintext, configuration: policy)
                    r["protected"] = p1
                    r["deterministic"] = p1 == p2
                case "access_with_config":
                    // 2-arg escape hatch: caller passes an explicit configuration name.
                    let p = try client.protect(plaintext, configuration: policy)
                    r["protected"] = p
                    let a = try client.access(p, configuration: policy)
                    r["accessed"] = a
                    r["roundtrip"] = a == plaintext
                case "access":
                    // 1-arg, header-driven primary path.
                    let p = try client.protect(plaintext, configuration: policy)
                    r["protected"] = p
                    let a = try client.access(p)
                    r["accessed"] = a
                    r["roundtrip"] = a == plaintext
                case "access_unknown_input":
                    _ = try client.access(inputOverride ?? "ZZZ12345")
                case "access_on_mask_output":
                    let m = try client.protect(plaintext, configuration: policy)
                    r["protected"] = m
                    _ = try client.access(m, configuration: policy)
                case "access_on_hash_output":
                    let h = try client.protect(plaintext, configuration: policy)
                    r["protected"] = h
                    _ = try client.access(h, configuration: policy)
                default:
                    errMsg = "unknown force_method: \(method)"
                }
            } catch {
                errMsg = error.localizedDescription
            }
            r["error"] = errMsg ?? NSNull()
            let errored = errMsg != nil
            r["expect_error_satisfied"] = errored == expectError
            if expectError, let mustContain = errorMustContain, errored {
                r["error_message_satisfied"] = errMsg!.lowercased().contains(mustContain.lowercased())
            }
            return r
        }

        // ─── default dispatch ───
        do {
            let protected = try client.protect(plaintext, configuration: policy)
            r["protected"] = protected

            let engineType = getEngine(input, policy: policy)

            if engineType == "mask" {
                if let expected = c["expected"] as? String {
                    r["matches_expected"] = protected == expected
                }
                r["reversible"] = false
                r["error"] = NSNull()
            } else if engineType == "hash" {
                let second = try client.protect(plaintext, configuration: policy)
                r["deterministic"] = protected == second
                r["reversible"] = false
                r["error"] = NSNull()
            } else {
                // Headered configs use the 1-arg primary path; headerless configs
                // need the 2-arg escape hatch (no header for the SDK to match on).
                let headerEnabled = isHeaderEnabled(input, policy: policy)
                let accessed: String
                if headerEnabled {
                    accessed = try client.access(protected)
                } else {
                    accessed = try client.access(protected, configuration: policy)
                }
                r["accessed"] = accessed
                r["roundtrip"] = accessed == plaintext
                r["error"] = NSNull()
            }
        } catch {
            r["protected"] = NSNull()
            r["roundtrip"] = false
            r["error"] = error.localizedDescription
        }

        return r
    }

    var out = input
    out["results"] = results
    out["runner"] = "swift"
    out["sdk_version"] = "0.0.1-alpha.5"
    return out
}

func getEngine(_ input: [String: Any], policy: String) -> String {
    if let config = input["config"] as? [String: Any],
       let policies = config["configurations"] as? [String: Any],
       let pol = policies[policy] as? [String: Any],
       let engine = pol["engine"] as? String {
        return engine
    }
    return "ff1"
}

func isHeaderEnabled(_ input: [String: Any], policy: String) -> Bool {
    if let config = input["config"] as? [String: Any],
       let policies = config["configurations"] as? [String: Any],
       let pol = policies[policy] as? [String: Any],
       let te = pol["header_enabled"] as? Bool {
        return te
    }
    return true
}
