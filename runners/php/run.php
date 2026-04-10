<?php

declare(strict_types=1);

require_once '/app/vendor/autoload.php';

use Cyphera\FF1;
use Cyphera\FF3;
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
    $input['sdk_version'] = '0.0.1-alpha.1';
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
        $policy = $c['policy'] ?? 'test';
        $plaintext = $c['plaintext'] ?? '';
        $r = $c;

        if (!$client) {
            $r['error'] = $clientError ?? 'no config provided';
            $results[] = $r;
            continue;
        }

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
                    $accessed = $client->access($protected);
                } else {
                    $accessed = $client->access($protected, $policy);
                }
                $r['accessed'] = $accessed;
                $r['roundtrip'] = $accessed === $plaintext;

                $accessedExplicit = $client->access($protected, $policy);
                $r['accessed_explicit'] = $accessedExplicit;
                $r['roundtrip_explicit'] = $accessedExplicit === $plaintext;
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
    $input['sdk_version'] = '0.0.1-alpha.1';
    return $input;
}

function getEngine(array $input, string $policy): string
{
    return $input['config']['policies'][$policy]['engine'] ?? 'ff1';
}

function isTagEnabled(array $input, string $policy): bool
{
    $te = $input['config']['policies'][$policy]['tag_enabled'] ?? null;
    return $te !== false;
}
