package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyphera-labs/cyphera-go"
	"github.com/cyphera-labs/cyphera-go/engine/ff1"
	"github.com/cyphera-labs/cyphera-go/engine/ff3"
)

// engineCipher is the common surface of the FF1 and FF3 ciphers.
type engineCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

func main() {
	inputDir := "inputs"
	outputDir := "results/go"
	if len(os.Args) > 1 {
		inputDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		outputDir = os.Args[2]
	}

	engineIn := filepath.Join(inputDir, "engine")
	engineOut := filepath.Join(outputDir, "engine")
	if _, err := os.Stat(engineIn); err == nil {
		os.MkdirAll(engineOut, 0755)
		files, _ := os.ReadDir(engineIn)
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			fmt.Printf("[engine] %s\n", f.Name())
			data := readJSON(filepath.Join(engineIn, f.Name()))
			result := runEngine(data)
			writeJSON(filepath.Join(engineOut, f.Name()), result)
		}
	}

	sdkIn := filepath.Join(inputDir, "sdk")
	sdkOut := filepath.Join(outputDir, "sdk")
	if _, err := os.Stat(sdkIn); err == nil {
		os.MkdirAll(sdkOut, 0755)
		files, _ := os.ReadDir(sdkIn)
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			fmt.Printf("[sdk] %s\n", f.Name())
			data := readJSON(filepath.Join(sdkIn, f.Name()))
			result := runSdk(data)
			writeJSON(filepath.Join(sdkOut, f.Name()), result)
		}
	}

	fmt.Printf("Done. Results in %s\n", outputDir)
}

func runEngine(data map[string]interface{}) map[string]interface{} {
	engine, _ := data["engine"].(string)
	if engine == "" {
		engine = "ff1"
	}
	globalAlpha, _ := data["alphabet"].(string)
	globalKey, _ := data["key"].(string)
	globalTweak, _ := data["tweak"].(string)
	_, isNist := data["source"]

	cases, _ := data["cases"].([]interface{})
	var results []interface{}

	for _, c := range cases {
		cm := c.(map[string]interface{})
		r := copyMap(cm)

		keyHex := getString(cm, "key", globalKey)
		tweakHex := getString(cm, "tweak", globalTweak)
		alphaStr := getString(cm, "alphabet", globalAlpha)
		if alphaStr == "" {
			alphaStr = "0123456789"
		}
		plaintext, _ := cm["plaintext"].(string)

		key, _ := hex.DecodeString(keyHex)
		tweak, _ := hex.DecodeString(tweakHex)

		var cipher engineCipher
		var err error
		switch engine {
		case "ff3":
			cipher, err = ff3.New(key, tweak, alphaStr)
		case "ff31":
			cipher, err = ff3.NewFF31(key, tweak, alphaStr)
		default:
			cipher, err = ff1.New(key, tweak, alphaStr)
		}
		if err != nil {
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}

		ct, err := cipher.Encrypt(plaintext)
		if err != nil {
			r["error"] = err.Error()
			r["ciphertext"] = nil
			r["roundtrip"] = false
			results = append(results, r)
			continue
		}

		dt, err := cipher.Decrypt(ct)
		if err != nil {
			r["error"] = err.Error()
			r["ciphertext"] = ct
			r["roundtrip"] = false
			results = append(results, r)
			continue
		}

		r["ciphertext"] = ct
		r["decrypted"] = dt
		r["roundtrip"] = dt == plaintext
		if isNist {
			if expected, ok := cm["expected"].(string); ok {
				r["matches_nist"] = ct == expected
			}
		}
		r["error"] = nil
		results = append(results, r)
	}

	out := copyMap(data)
	out["results"] = results
	out["runner"] = "go"
	out["sdk_version"] = "0.0.1-alpha.8"
	return out
}

func runSdk(data map[string]interface{}) map[string]interface{} {
	var client *cyphera.Cyphera
	var clientErr error
	if cfg, ok := data["config"]; ok && cfg != nil {
		client, clientErr = buildClient(cfg)
	} else {
		clientErr = fmt.Errorf("no config provided")
	}

	cases, _ := data["cases"].([]interface{})
	var results []interface{}

	for _, c := range cases {
		cm, _ := c.(map[string]interface{})
		r := copyMap(cm)

		configurationName := getString(cm, "configuration", "test")
		plaintext, _ := cm["plaintext"].(string)
		forceMethod, _ := cm["force_method"].(string)
		expectError, _ := cm["expect_error"].(bool)
		errorMustContain, _ := cm["error_must_contain"].(string)
		inputOverride, _ := cm["input_override"].(string)

		if client == nil {
			msg := "no config provided"
			if clientErr != nil {
				msg = clientErr.Error()
			}
			r["error"] = msg
			r["expect_error_satisfied"] = expectError
			results = append(results, r)
			continue
		}

		// ─── force_method dispatch ───
		if forceMethod != "" {
			var dispatchErr error
			switch forceMethod {
			case "protect_only":
				protected, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				r["protected"] = protected
				if expected, ok := cm["expected"].(string); ok {
					r["matches_expected"] = protected == expected
				}
			case "protect_only_deterministic":
				p1, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				p2, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				r["protected"] = p1
				r["deterministic"] = p1 == p2
			case "access":
				// 1-arg, header-driven primary path.
				protected, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				r["protected"] = protected
				accessed, err := client.Access(protected)
				if err != nil {
					dispatchErr = err
					break
				}
				r["accessed"] = accessed
				r["roundtrip"] = accessed == plaintext
			case "access_with_config":
				// 2-arg escape hatch: caller passes an explicit configuration name.
				protected, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				r["protected"] = protected
				accessed, err := client.AccessWithConfig(configurationName, protected)
				if err != nil {
					dispatchErr = err
					break
				}
				r["accessed"] = accessed
				r["roundtrip"] = accessed == plaintext
			case "access_unknown_input":
				v := inputOverride
				if v == "" {
					v = "ZZZ12345"
				}
				_, err := client.Access(v)
				if err != nil {
					dispatchErr = err
				}
			case "access_on_mask_output", "access_on_hash_output":
				protected, err := client.Protect(plaintext, configurationName)
				if err != nil {
					dispatchErr = err
					break
				}
				r["protected"] = protected
				_, err = client.AccessWithConfig(configurationName, protected)
				if err != nil {
					dispatchErr = err
				}
			default:
				dispatchErr = fmt.Errorf("unknown force_method: %s", forceMethod)
			}

			if dispatchErr != nil {
				r["error"] = dispatchErr.Error()
			} else {
				r["error"] = nil
			}
			errored := dispatchErr != nil
			r["expect_error_satisfied"] = errored == expectError
			if expectError && errorMustContain != "" && errored {
				r["error_message_satisfied"] = strings.Contains(
					strings.ToLower(dispatchErr.Error()),
					strings.ToLower(errorMustContain),
				)
			}
			results = append(results, r)
			continue
		}

		// ─── default dispatch ───
		engineType := getConfigField(data, configurationName, "engine", "ff1")
		headerEnabled := getConfigBool(data, configurationName, "header_enabled", true)

		protected, err := client.Protect(plaintext, configurationName)
		if err != nil {
			r["protected"] = nil
			r["roundtrip"] = false
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}
		r["protected"] = protected

		switch engineType {
		case "mask":
			if expected, ok := cm["expected"].(string); ok {
				r["matches_expected"] = protected == expected
			}
			r["reversible"] = false
			r["error"] = nil
		case "hash":
			second, err := client.Protect(plaintext, configurationName)
			if err == nil {
				r["deterministic"] = protected == second
			}
			r["reversible"] = false
			r["error"] = nil
		default:
			// Headered configs use the 1-arg primary path; headerless use the
			// 2-arg escape hatch.
			var accessed string
			var aerr error
			if headerEnabled {
				accessed, aerr = client.Access(protected)
			} else {
				accessed, aerr = client.AccessWithConfig(configurationName, protected)
			}
			if aerr != nil {
				r["roundtrip"] = false
				r["error"] = aerr.Error()
			} else {
				r["accessed"] = accessed
				r["roundtrip"] = accessed == plaintext
				r["error"] = nil
			}
		}
		results = append(results, r)
	}

	out := copyMap(data)
	out["results"] = results
	out["runner"] = "go"
	out["sdk_version"] = "0.0.1-alpha.8"
	return out
}

// buildClient materialises a cyphera.Cyphera from the JSON config blob by
// round-tripping through the SDK's own Config struct.
func buildClient(raw interface{}) (*cyphera.Cyphera, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var cfg cyphera.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return cyphera.FromConfig(cfg)
}

func getConfigField(data map[string]interface{}, configurationName, field, fallback string) string {
	cfg, ok := data["config"].(map[string]interface{})
	if !ok {
		return fallback
	}
	confs, ok := cfg["configurations"].(map[string]interface{})
	if !ok {
		return fallback
	}
	p, ok := confs[configurationName].(map[string]interface{})
	if !ok {
		return fallback
	}
	if v, ok := p[field].(string); ok {
		return v
	}
	return fallback
}

func getConfigBool(data map[string]interface{}, configurationName, field string, fallback bool) bool {
	cfg, ok := data["config"].(map[string]interface{})
	if !ok {
		return fallback
	}
	confs, ok := cfg["configurations"].(map[string]interface{})
	if !ok {
		return fallback
	}
	p, ok := confs[configurationName].(map[string]interface{})
	if !ok {
		return fallback
	}
	if v, ok := p[field].(bool); ok {
		return v
	}
	return fallback
}

func getString(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range m {
		out[k] = v
	}
	return out
}

func readJSON(path string) map[string]interface{} {
	data, _ := os.ReadFile(path)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	return m
}

func writeJSON(path string, data map[string]interface{}) {
	b, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, b, 0644)
}
