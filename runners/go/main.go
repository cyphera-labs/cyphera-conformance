package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyphera-labs/cyphera-go/alphabet"
	"github.com/cyphera-labs/cyphera-go/engine/ff1"
)

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
			if !strings.HasSuffix(f.Name(), ".json") || strings.Contains(f.Name(), "ff3") {
				continue
			}
			fmt.Printf("[engine] %s\n", f.Name())
			data := readJSON(filepath.Join(engineIn, f.Name()))
			result := runFF1Engine(data)
			writeJSON(filepath.Join(engineOut, f.Name()), result)
		}
	}

	fmt.Printf("Done. Results in %s\n", outputDir)
}

func runFF1Engine(data map[string]interface{}) map[string]interface{} {
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

		alpha, err := alphabet.NewAlphabet(alphaStr)
		if err != nil {
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}

		cipher, err := ff1.NewCipher(alpha.Radix(), key, tweak)
		if err != nil {
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}

		ct, err := cipher.EncryptStringWithAlphabet(plaintext, tweak, alpha)
		if err != nil {
			r["error"] = err.Error()
			r["ciphertext"] = nil
			r["roundtrip"] = false
			results = append(results, r)
			continue
		}

		dt, err := cipher.DecryptStringWithAlphabet(ct, tweak, alpha)
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
	out["sdk_version"] = "0.0.0-dev"
	return out
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
