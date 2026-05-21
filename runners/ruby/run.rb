#!/usr/bin/env ruby
require "json"
require "fileutils"
require "cyphera"

input_dir = ARGV[0] || "inputs"
output_dir = ARGV[1] || "results/ruby"
SDK_VERSION = "0.0.1.alpha.3"

def hex_to_bytes(hex)
  return "" if hex.nil? || hex.empty?
  [hex].pack("H*")
end

def run_engine(data)
  engine = data["engine"] || "ff1"
  global_alpha = data["alphabet"]
  global_key = data["key"]
  global_tweak = data["tweak"]
  is_nist = data.key?("source")

  results = (data["cases"] || []).map do |c|
    r = c.dup
    key_hex = c["key"] || global_key || ""
    tweak_hex = c["tweak"] || global_tweak || ""
    alpha = c["alphabet"] || global_alpha || "0123456789"
    pt = c["plaintext"] || ""

    begin
      key = hex_to_bytes(key_hex)
      tweak = hex_to_bytes(tweak_hex)
      cipher = engine == "ff3" ? Cyphera::FF3.new(key, tweak, alpha) : Cyphera::FF1.new(key, tweak, alpha)
      ct = cipher.encrypt(pt)
      dt = cipher.decrypt(ct)
      r["ciphertext"] = ct
      r["decrypted"] = dt
      r["roundtrip"] = dt == pt
      r["matches_nist"] = ct == c["expected"] if is_nist && c["expected"]
      r["error"] = nil
    rescue => e
      r["ciphertext"] = nil
      r["decrypted"] = nil
      r["roundtrip"] = false
      r["error"] = e.message
    end
    r
  end

  data.merge("results" => results, "runner" => "ruby", "sdk_version" => SDK_VERSION)
end

def run_sdk(data)
  client = nil
  client_err = nil
  begin
    client = Cyphera::Client.new(data["config"]) if data["config"]
  rescue => e
    client_err = e.message
  end

  results = (data["cases"] || []).map do |c|
    r = c.dup
    policy = c["configuration"] || "test"
    pt = c["plaintext"] || ""
    force_method = c["force_method"]
    expect_error = c["expect_error"] || false
    error_must_contain = c["error_must_contain"]
    input_override = c["input_override"]

    if client.nil?
      r["error"] = client_err || "no config provided"
      r["expect_error_satisfied"] = expect_error
      next r
    end

    # ─── force_method dispatch ───
    if force_method
      err = nil
      begin
        case force_method
        when "protect_only"
          p = client.protect(pt, policy)
          r["protected"] = p
          r["matches_expected"] = (p == c["expected"]) if c.key?("expected")
        when "protect_only_deterministic"
          p1 = client.protect(pt, policy)
          p2 = client.protect(pt, policy)
          r["protected"] = p1
          r["deterministic"] = p1 == p2
        when "access"
          p = client.protect(pt, policy)
          r["protected"] = p
          a = client.access(p, policy)
          r["accessed"] = a
          r["roundtrip"] = a == pt
        when "access_by_header"
          p = client.protect(pt, policy)
          r["protected"] = p
          a = client.access_by_header(p)
          r["accessed"] = a
          r["roundtrip"] = a == pt
        when "access_by_header_unknown_prefix"
          client.access_by_header(input_override || "ZZZ12345")
        when "access_on_mask_output"
          m = client.protect(pt, policy)
          r["protected"] = m
          client.access(m, policy)
        when "access_on_hash_output"
          h = client.protect(pt, policy)
          r["protected"] = h
          client.access(h, policy)
        else
          err = "unknown force_method: #{force_method}"
        end
      rescue => e
        err = e.message
      end
      r["error"] = err
      errored = !err.nil?
      r["expect_error_satisfied"] = (errored == expect_error)
      if expect_error && error_must_contain && errored
        r["error_message_satisfied"] = err.downcase.include?(error_must_contain.downcase)
      end
      next r
    end

    # ─── default dispatch ───
    begin
      protected_val = client.protect(pt, policy)
      r["protected"] = protected_val

      cfg = (data["config"]["configurations"] || {})[policy] || {}
      engine_type = cfg["engine"] || "ff1"
      tag_enabled = cfg.fetch("header_enabled", true)

      if engine_type == "mask"
        r["matches_expected"] = (protected_val == c["expected"]) if c.key?("expected")
        r["reversible"] = false
        r["error"] = nil
      elsif engine_type == "hash"
        second = client.protect(pt, policy)
        r["deterministic"] = protected_val == second
        r["reversible"] = false
        r["error"] = nil
      else
        if tag_enabled
          accessed = client.access_by_header(protected_val)
          r["accessed"] = accessed
          r["roundtrip"] = accessed == pt
          begin
            client.access(protected_val, policy)
            r["explicit_on_headered_errored"] = false
          rescue
            r["explicit_on_headered_errored"] = true
          end
        else
          accessed = client.access(protected_val, policy)
          r["accessed"] = accessed
          r["roundtrip"] = accessed == pt
        end
        r["error"] = nil
      end
    rescue => e
      r["protected"] = nil
      r["roundtrip"] = false
      r["error"] = e.message
    end
    r
  end

  data.merge("results" => results, "runner" => "ruby", "sdk_version" => SDK_VERSION)
end

# Engine tests
engine_in = File.join(input_dir, "engine")
engine_out = File.join(output_dir, "engine")
if Dir.exist?(engine_in)
  FileUtils.mkdir_p(engine_out)
  Dir.glob(File.join(engine_in, "*.json")).sort.each do |f|
    name = File.basename(f)
    puts "[engine] #{name}"
    data = JSON.parse(File.read(f))
    result = run_engine(data)
    File.write(File.join(engine_out, name), JSON.pretty_generate(result))
  end
end

# SDK tests
sdk_in = File.join(input_dir, "sdk")
sdk_out = File.join(output_dir, "sdk")
if Dir.exist?(sdk_in)
  FileUtils.mkdir_p(sdk_out)
  Dir.glob(File.join(sdk_in, "*.json")).sort.each do |f|
    name = File.basename(f)
    puts "[sdk] #{name}"
    data = JSON.parse(File.read(f))
    result = run_sdk(data)
    File.write(File.join(sdk_out, name), JSON.pretty_generate(result))
  end
end

puts "Done. Results in #{output_dir}"
