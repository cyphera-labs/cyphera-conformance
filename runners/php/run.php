<?php

declare(strict_types=1);

require_once '/app/vendor/autoload.php';

use Cyphera\FF1;
use Cyphera\FF3;
use Cyphera\FF31;
use Cyphera\Cyphera;

$inputDir = $argv[1] ?? 'inputs';
$outputDir = $argv[2] ?? 'results/php';

// Engine tests
$engineDir = "$inputDir/engine";
$engineOut = "$outputDir/engine";
if (is_dir($engineDir)) {
    @mkdir($engineOut, 0755, true);
    foreach (glob("$engineDir/*.json") as $file) {
        $name = basename($file);
        echo "[engine] $name\n";
        $input = json_decode(file_get_contents($file), true);
        $result = runEngine($input);
        file_put_contents("$engineOut/$name", json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

// SDK tests
$sdkDir = "$inputDir/sdk";
$sdkOut = "$outputDir/sdk";
if (is_dir($sdkDir)) {
    @mkdir($sdkOut, 0755, true);
    foreach (glob("$sdkDir/*.json") as $file) {
        $name = basename($file);
        echo "[sdk] $name\n";
        $input = json_decode(file_get_contents($file), true);
        $result = runSdk($input);
        file_put_contents("$sdkOut/$name", json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

echo "Done. Results in $outputDir\n";

function hexToBytes(string $hex): string
{
    if ($hex === '') return '';
    return hex2bin($hex);
}

function runEngine(array $input): array
{
    $engine = $input['engine'] ?? 'ff1';
    $globalAlphabet = $input['alphabet'] ?? null;
    $globalKey = $input['key'] ?? null;
    $globalTweak = $input['tweak'] ?? null;
    $isNist = isset($input['source']);

    $results = [];
    foreach ($input['cases'] as $c) {
        $keyHex = $c['key'] ?? $globalKey ?? '';
        $tweakHex = array_key_exists('tweak', $c) ? $c['tweak'] : ($globalTweak ?? '');
        $alpha = $c['alphabet'] ?? $globalAlphabet ?? '0123456789';
        $plaintext = $c['plaintext'] ?? '';
        $r = $c;

        try {
            $key = hexToBytes($keyHex);
            $tweak = hexToBytes($tweakHex);

            if ($engine === 'ff3') {
                $cipher = new FF3($key, $tweak, $alpha);
            } elseif ($engine === 'ff31') {
                $cipher = new FF31($key, $tweak, $alpha);
            } else {
                $cipher = new FF1($key, $tweak, $alpha);
            }

            $encrypted = $cipher->encrypt($plaintext);
            $decrypted = $cipher->decrypt($encrypted);

            $r['ciphertext'] = $encrypted;
            $r['decrypted'] = $decrypted;
            $r['roundtrip'] = $decrypted === $plaintext;
            if ($isNist && isset($c['expected'])) {
                $r['matches_nist'] = $encrypted === $c['expected'];
            }
            $r['error'] = null;
        } catch (\Throwable $e) {
            $r['ciphertext'] = null;
            $r['decrypted'] = null;
            $r['roundtrip'] = false;
            $r['error'] = $e->getMessage();
        }

        $results[] = $r;
    }

    $input['results'] = $results;
    $input['runner'] = 'php';
    $input['sdk_version'] = '0.0.1-alpha.5';
    return $input;
}

function runSdk(array $input): array
{
    $config = $input['config'] ?? null;
    $client = null;
    $clientError = null;

    if ($config) {
        try {
            $client = Cyphera::fromConfig($config);
        } catch (\Throwable $e) {
            $clientError = $e->getMessage();
        }
    }

    $results = [];
    foreach ($input['cases'] as $c) {
        $policy = $c['configuration'] ?? 'test';
        $plaintext = $c['plaintext'] ?? '';
        $forceMethod = $c['force_method'] ?? null;
        $expectError = $c['expect_error'] ?? false;
        $errorMustContain = $c['error_must_contain'] ?? null;
        $inputOverride = $c['input_override'] ?? null;
        $r = $c;

        if (!$client) {
            $r['error'] = $clientError ?? 'no config provided';
            $r['expect_error_satisfied'] = $expectError;
            $results[] = $r;
            continue;
        }

        // ─── force_method dispatch ───
        if ($forceMethod !== null) {
            $errMsg = null;
            try {
                switch ($forceMethod) {
                    case 'protect_only':
                        $p = $client->protect($plaintext, $policy);
                        $r['protected'] = $p;
                        if (isset($c['expected'])) $r['matches_expected'] = $p === $c['expected'];
                        break;
                    case 'protect_only_deterministic':
                        $p1 = $client->protect($plaintext, $policy);
                        $p2 = $client->protect($plaintext, $policy);
                        $r['protected'] = $p1;
                        $r['deterministic'] = $p1 === $p2;
                        break;
                    case 'access':
                        $p = $client->protect($plaintext, $policy);
                        $r['protected'] = $p;
                        $a = $client->access($p, $policy);
                        $r['accessed'] = $a;
                        $r['roundtrip'] = $a === $plaintext;
                        break;
                    case 'access_by_header':
                        $p = $client->protect($plaintext, $policy);
                        $r['protected'] = $p;
                        $a = $client->accessByHeader($p);
                        $r['accessed'] = $a;
                        $r['roundtrip'] = $a === $plaintext;
                        break;
                    case 'access_by_header_unknown_prefix':
                        $client->accessByHeader($inputOverride ?? 'ZZZ12345');
                        break;
                    case 'access_on_mask_output':
                        $m = $client->protect($plaintext, $policy);
                        $r['protected'] = $m;
                        $client->access($m, $policy);
                        break;
                    case 'access_on_hash_output':
                        $h = $client->protect($plaintext, $policy);
                        $r['protected'] = $h;
                        $client->access($h, $policy);
                        break;
                    default:
                        $errMsg = "unknown force_method: $forceMethod";
                }
            } catch (\Throwable $e) {
                $errMsg = $e->getMessage();
            }
            $r['error'] = $errMsg;
            $errored = $errMsg !== null;
            $r['expect_error_satisfied'] = $errored === $expectError;
            if ($expectError && $errorMustContain !== null && $errored) {
                $r['error_message_satisfied'] = stripos($errMsg, $errorMustContain) !== false;
            }
            $results[] = $r;
            continue;
        }

        // ─── default dispatch ───
        try {
            $protected = $client->protect($plaintext, $policy);
            $r['protected'] = $protected;

            $engineType = getEngine($input, $policy);

            if ($engineType === 'mask') {
                if (isset($c['expected'])) {
                    $r['matches_expected'] = $protected === $c['expected'];
                }
                $r['reversible'] = false;
                $r['error'] = null;
            } elseif ($engineType === 'hash') {
                $second = $client->protect($plaintext, $policy);
                $r['deterministic'] = $protected === $second;
                $r['reversible'] = false;
                $r['error'] = null;
            } else {
                $tagEnabled = isTagEnabled($input, $policy);

                if ($tagEnabled) {
                    $accessed = $client->accessByHeader($protected);
                    $r['accessed'] = $accessed;
                    $r['roundtrip'] = $accessed === $plaintext;
                    try {
                        $client->access($protected, $policy);
                        $r['explicit_on_headered_errored'] = false;
                    } catch (\Throwable $_) {
                        $r['explicit_on_headered_errored'] = true;
                    }
                } else {
                    $accessed = $client->access($protected, $policy);
                    $r['accessed'] = $accessed;
                    $r['roundtrip'] = $accessed === $plaintext;
                }
                $r['error'] = null;
            }
        } catch (\Throwable $e) {
            $r['protected'] = null;
            $r['roundtrip'] = false;
            $r['error'] = $e->getMessage();
        }

        $results[] = $r;
    }

    $input['results'] = $results;
    $input['runner'] = 'php';
    $input['sdk_version'] = '0.0.1-alpha.5';
    return $input;
}

function getEngine(array $input, string $policy): string
{
    return $input['config']['configurations'][$policy]['engine'] ?? 'ff1';
}

function isTagEnabled(array $input, string $policy): bool
{
    $te = $input['config']['configurations'][$policy]['header_enabled'] ?? null;
    return $te !== false;
}
