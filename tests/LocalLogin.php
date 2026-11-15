<?php

declare(strict_types=1);

namespace Rante\Apps\Tests;

use Firebase\JWT\JWT;
use Rante\Apps\Http\HttpClient;
use Rante\Apps\Http\HttpResponse;

/**
 * A stand-in for Rante Login's key publishing that answers in process (no network): the OpenID configuration and the
 * JWKS, with keys generated for the run, plus a signer that builds the tokens of conformance/tokens.json.
 */
final class LocalLogin implements HttpClient
{
    public const ORIGIN = 'https://login.test';

    public int $discoveryCount = 0;
    public int $jwksCount = 0;
    /** ok, not-found (discovery answers 404), other-issuer or down (the request fails). */
    public string $mode = 'ok';

    private \OpenSSLAsymmetricKey $rsa1;
    private \OpenSSLAsymmetricKey $rsa2;
    private \OpenSSLAsymmetricKey $rsaOther;
    private \OpenSSLAsymmetricKey $ec1;
    /** @var list<array<string, string>> */
    private array $published;

    public function __construct()
    {
        $this->rsa1 = Keys::rsa();
        $this->rsa2 = Keys::rsa();
        $this->rsaOther = Keys::rsa();
        $this->ec1 = Keys::ec();
        $this->published = [self::rsaJwk($this->rsa1, 'key-1'), self::ecJwk($this->ec1, 'ec-1')];
    }

    public function get(string $url): HttpResponse
    {
        if ($this->mode === 'down') {
            throw new \RuntimeException('connection refused');
        }
        $path = (string) parse_url($url, PHP_URL_PATH);
        if ($path === '/common/v2.0/.well-known/openid-configuration') {
            $this->discoveryCount++;
            if ($this->mode === 'not-found') {
                return new HttpResponse(404, '');
            }
            $issuer = $this->mode === 'other-issuer' ? 'https://evil.example/common/v2.0' : self::ORIGIN . '/common/v2.0';
            return new HttpResponse(200, (string) json_encode(['issuer' => $issuer, 'jwks_uri' => self::ORIGIN . '/common/discovery/v2.0/keys']));
        }
        if ($path === '/common/discovery/v2.0/keys') {
            $this->jwksCount++;
            return new HttpResponse(200, (string) json_encode(['keys' => $this->published]));
        }
        return new HttpResponse(404, '');
    }

    public function publishSecondKey(): void
    {
        $this->published[] = self::rsaJwk($this->rsa2, 'key-2');
    }

    /** @return array<string, string> */
    private static function rsaJwk(\OpenSSLAsymmetricKey $key, string $kid): array
    {
        $rsa = openssl_pkey_get_details($key)['rsa'];
        return ['kty' => 'RSA', 'n' => JWT::urlsafeB64Encode($rsa['n']), 'e' => JWT::urlsafeB64Encode($rsa['e']), 'kid' => $kid, 'alg' => 'RS256', 'use' => 'sig'];
    }

    /** @return array<string, string> */
    private static function ecJwk(\OpenSSLAsymmetricKey $key, string $kid): array
    {
        $ec = openssl_pkey_get_details($key)['ec'];
        return [
            'kty' => 'EC', 'crv' => 'P-256',
            'x' => JWT::urlsafeB64Encode(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => JWT::urlsafeB64Encode(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)),
            'kid' => $kid, 'alg' => 'ES256', 'use' => 'sig',
        ];
    }

    /** Converts a DER ECDSA signature to the raw r || s form JWS uses. */
    private static function derToRaw(string $der): string
    {
        $offset = 2;
        if (ord($der[1]) & 0x80) {
            $offset += ord($der[1]) & 0x7f;
        }
        $parts = [];
        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $value = ltrim(substr($der, $offset + 2, $length), "\0");
            $parts[] = str_pad($value, 32, "\0", STR_PAD_LEFT);
            $offset += 2 + $length;
        }
        return $parts[0] . $parts[1];
    }

    /**
     * Signs header + claims. how: key-1 | key-2 | other-key | es256 | hs256-public-key | none.
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public function token(array $header, array $claims, string $how = 'key-1'): string
    {
        switch ($how) {
            case 'es256':
                $header['alg'] = 'ES256';
                $header['kid'] = 'ec-1';
                break;
            case 'hs256-public-key':
                $header['alg'] = 'HS256';
                break;
            case 'none':
                $header['alg'] = 'none';
                break;
            case 'key-2':
                $header['kid'] = 'key-2';
                break;
        }
        $input = JWT::urlsafeB64Encode((string) json_encode($header, JSON_UNESCAPED_SLASHES)) . '.'
            . JWT::urlsafeB64Encode((string) json_encode($claims, JSON_UNESCAPED_SLASHES));
        $signature = '';
        switch ($how) {
            case 'none':
                break;
            case 'es256':
                openssl_sign($input, $der, $this->ec1, OPENSSL_ALGO_SHA256);
                $signature = self::derToRaw($der);
                break;
            case 'hs256-public-key':
                $signature = hash_hmac('sha256', $input, Keys::publicPem($this->rsa1), true);
                break;
            case 'other-key':
                openssl_sign($input, $signature, $this->rsaOther, OPENSSL_ALGO_SHA256);
                break;
            case 'key-2':
                openssl_sign($input, $signature, $this->rsa2, OPENSSL_ALGO_SHA256);
                break;
            default:
                openssl_sign($input, $signature, $this->rsa1, OPENSSL_ALGO_SHA256);
        }
        return $input . '.' . JWT::urlsafeB64Encode($signature);
    }

    // ------------------------------------------------------------------------------------------- conformance cases

    /** @return array<string, mixed> */
    public static function cases(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/conformance/tokens.json'), true, 64, JSON_THROW_ON_ERROR);
    }

    /**
     * Replaces the placeholders of conformance/tokens.json (see its description).
     *
     * @param array<string, mixed> $doc
     */
    public static function resolve(array $doc, mixed $value, int $now): mixed
    {
        if (is_string($value)) {
            if (preg_match('/^\$now([+-]\d+)?$/', $value, $m) === 1) {
                return $now + (isset($m[1]) ? (int) $m[1] : 0);
            }
            return strtr(str_replace('$iss', '$authority/$tenantId/v2.0', $value), [
                '$authority' => self::ORIGIN,
                '$CLIENTID' => strtoupper($doc['clientId']),
                '$clientId' => $doc['clientId'],
                '$TENANTID' => strtoupper($doc['tenantId']),
                '$otherTenantId' => $doc['otherTenantId'],
                '$tenantId' => $doc['tenantId'],
                '$userId' => $doc['userId'],
            ]);
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = self::resolve($doc, $v, $now);
            }
            return $out;
        }
        return $value;
    }

    /**
     * Builds the token of one conformance case.
     *
     * @param array<string, mixed> $doc
     * @param array<string, mixed> $case
     */
    public function buildToken(array $doc, array $case, int $now): string
    {
        if (array_key_exists('raw', $case)) {
            return $case['raw'];
        }
        $header = self::resolve($doc, $doc['header'], $now);
        foreach (self::resolve($doc, $case['header'] ?? [], $now) as $k => $v) {
            $header[$k] = $v;
        }
        $claims = self::resolve($doc, $doc['claims'], $now);
        foreach (self::resolve($doc, $case['claims'] ?? [], $now) as $k => $v) {
            if ($v === null) {
                unset($claims[$k]);
            } else {
                $claims[$k] = $v;
            }
        }
        $token = $this->token($header, $claims, $case['sign'] ?? 'key-1');
        if (($case['tamper'] ?? false) === true) {
            $parts = explode('.', $token);
            $parts[1] = JWT::urlsafeB64Encode((string) json_encode(['oid' => '00000000-aaaa-bbbb-cccc-000000000000'] + $claims, JSON_UNESCAPED_SLASHES));
            $token = implode('.', $parts);
        }
        return $token;
    }
}
