<?php

declare(strict_types=1);

namespace Rante\Apps;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Psr\SimpleCache\CacheInterface;
use Rante\Apps\Http\CurlHttpClient;
use Rante\Apps\Http\HttpClient;

/**
 * Checks Rante app access tokens for one app, as described in docs/tokens.md of
 * github.com/rante-corporation/rante-apps-sdk. Create one per app and reuse it: it caches Rante Login's signing keys
 * (in memory, and in a PSR-16 cache when one is given, so PHP-FPM requests share them).
 */
final class RanteAppTokenVerifier
{
    private const GUID = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';
    private const JWT_SHAPE = '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/';
    private const SUPPORTED_ALGORITHMS = ['RS256', 'ES256'];
    private const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]', '::1'];

    private readonly string $clientId;
    /** @var list<string> */
    private readonly array $audiences;
    private readonly string $authority;
    /** @var list<string>|null */
    private readonly ?array $tenants;
    /** @var list<string> */
    private readonly array $requiredScopes;
    /** @var list<string> */
    private readonly array $algorithms;
    private readonly HttpClient $http;
    private readonly string $cacheKey;

    /** @var array{keys: array<string, array<string, mixed>>, fetchedAt: int, jwksUri: string}|null */
    private ?array $snapshot = null;

    /**
     * @param string $clientId your app's Application (client) ID
     * @param list<string> $tenants accept tokens of these tenants only
     * @param list<string> $requiredScopes scopes every token must have (from its scp claim)
     * @param list<string> $extraAudiences audiences accepted besides the client ID, such as api://{clientId}
     * @param string $authority default https://login.rante.com; http is accepted for localhost only, for tests
     * @param int $clockSkew seconds of clock difference tolerated for exp, nbf and iat
     * @param list<string> $algorithms RS256 and ES256 are supported
     * @param float $timeout seconds for each request to Rante Login
     * @param int $jwksCooldown minimum seconds between two key fetches (an unknown kid triggers one)
     * @param int $jwksMaxAge seconds fetched keys are used before they are fetched again
     * @throws RanteAppsException invalid_configuration
     */
    public function __construct(
        string $clientId,
        array $tenants = [],
        array $requiredScopes = [],
        array $extraAudiences = [],
        string $authority = RanteApps::DEFAULT_AUTHORITY,
        private readonly int $clockSkew = 60,
        array $algorithms = ['RS256'],
        float $timeout = 5.0,
        private readonly int $jwksCooldown = 30,
        private readonly int $jwksMaxAge = 600,
        ?HttpClient $httpClient = null,
        private readonly ?CacheInterface $cache = null,
    ) {
        if (preg_match(self::GUID, $clientId) !== 1) {
            throw self::config("clientId must be your app's Application (client) ID, a GUID.");
        }
        $this->clientId = strtolower($clientId);
        $audiences = [$this->clientId];
        foreach ($extraAudiences as $audience) {
            if (!is_string($audience) || $audience === '') {
                throw self::config('extraAudiences has an invalid entry.');
            }
            $audiences[] = strtolower($audience);
        }
        $this->audiences = $audiences;
        $this->authority = self::normalizeAuthority($authority);
        $allowed = [];
        foreach ($tenants as $tenant) {
            if (!is_string($tenant) || preg_match(self::GUID, $tenant) !== 1) {
                throw self::config('tenants has an invalid entry: ' . json_encode($tenant) . '.');
            }
            $allowed[] = strtolower($tenant);
        }
        $this->tenants = $allowed === [] ? null : $allowed;
        foreach ($requiredScopes as $scope) {
            if (!is_string($scope) || $scope === '' || preg_match('/\s/', $scope) === 1) {
                throw self::config('requiredScopes has an invalid entry: ' . json_encode($scope) . '.');
            }
        }
        $this->requiredScopes = array_values($requiredScopes);
        if ($clockSkew < 0 || $clockSkew > 600) {
            throw self::config('clockSkew must be a number of seconds from 0 to 600.');
        }
        if ($algorithms === [] || array_diff($algorithms, self::SUPPORTED_ALGORITHMS) !== []) {
            throw self::config('algorithms must be a non-empty subset of RS256, ES256.');
        }
        $this->algorithms = array_values($algorithms);
        if ($timeout <= 0 || $jwksCooldown < 0 || $jwksMaxAge <= 0) {
            throw self::config('timeout and jwksMaxAge must be positive, jwksCooldown not negative.');
        }
        $this->http = $httpClient ?? new CurlHttpClient($timeout);
        $this->cacheKey = 'rante-apps.jwks.' . sha1($this->authority);
    }

    /** Your client ID, in lower case. */
    public function clientId(): string
    {
        return $this->clientId;
    }

    /** The authority, such as https://login.rante.com. */
    public function authority(): string
    {
        return $this->authority;
    }

    /**
     * Verifies a raw JWT (without "Bearer ") and returns who it is for.
     *
     * @throws RanteAppsException the token is missing or refused, or Rante Login could not be reached
     */
    public function verify(?string $token): RanteAppPrincipal
    {
        if ($token === null || $token === '') {
            throw new RanteAppsException('missing_token', 'No access token was sent.');
        }
        if (strlen($token) > 16384 || preg_match(self::JWT_SHAPE, $token) !== 1) {
            throw self::invalid('The access token is not a JSON Web Token.');
        }
        $parts = explode('.', $token);
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
        if (!is_array($header)) {
            throw self::invalid('The access token header cannot be read.');
        }
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !in_array($alg, $this->algorithms, true)) {
            throw self::invalid('The access token is signed with ' . (is_string($alg) ? $alg : 'no algorithm') . ', which is not accepted.');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw self::invalid('The access token names no signing key (kid).');
        }
        $jwk = $this->signingKey($kid);
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            throw self::invalid("The access token's algorithm does not match its signing key.");
        }
        try {
            $key = JWK::parseKey($jwk, $alg);
        } catch (\Throwable $e) {
            throw self::invalid('The signing key of the access token cannot be used.', $e);
        }
        if (!$key instanceof Key) {
            throw self::invalid('The signing key of the access token cannot be used.');
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->clockSkew;
        try {
            JWT::decode($token, $key);
        } catch (ExpiredException $e) {
            throw new RanteAppsException('token_expired', 'The access token has expired.', [], $e);
        } catch (SignatureInvalidException $e) {
            throw self::invalid('The access token signature is not valid.', $e);
        } catch (BeforeValidException $e) {
            throw self::invalid('The access token is not valid yet (nbf or iat).', $e);
        } catch (\Throwable $e) {
            throw self::invalid('The access token is not valid (' . (new \ReflectionClass($e))->getShortName() . ').', $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        try {
            $claims = json_decode(JWT::urlsafeB64Decode($parts[1]), true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw self::invalid('The access token payload is not JSON.', $e);
        }
        if (!is_array($claims) || ($claims !== [] && array_is_list($claims))) {
            throw self::invalid('The access token payload is not a JSON object.');
        }
        return $this->principal($claims);
    }

    /** @param array<string, mixed> $claims */
    private function principal(array $claims): RanteAppPrincipal
    {
        $now = time();
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            throw self::invalid('The access token has no expiry (exp).');
        }
        if ($exp <= $now - $this->clockSkew) {
            throw new RanteAppsException('token_expired', 'The access token has expired.');
        }
        if (array_key_exists('nbf', $claims) && (!is_int($claims['nbf']) && !is_float($claims['nbf']) || $claims['nbf'] > $now + $this->clockSkew)) {
            throw self::invalid('The access token is not valid yet (nbf).');
        }
        $iat = $claims['iat'] ?? null;
        if (array_key_exists('iat', $claims) && (!is_int($iat) && !is_float($iat) || $iat > $now + $this->clockSkew)) {
            throw self::invalid('The access token was issued in the future (iat).');
        }
        $tid = $claims['tid'] ?? null;
        if (!is_string($tid) || preg_match(self::GUID, $tid) !== 1) {
            throw self::invalid('The access token names no valid tenant (tid).');
        }
        $tenantId = strtolower($tid);
        $iss = $claims['iss'] ?? null;
        if (!is_string($iss) || strcasecmp($iss, $this->authority . '/' . $tenantId . '/v2.0') !== 0) {
            throw self::invalid('The access token was not issued by Rante Login for its tenant (iss).');
        }
        if (!$this->audienceMatches($claims['aud'] ?? null)) {
            throw self::invalid('The access token was issued for another app (aud).');
        }
        $oid = $claims['oid'] ?? null;
        if (!is_string($oid) || preg_match(self::GUID, $oid) !== 1) {
            throw self::invalid('The access token names no person (oid).');
        }
        if (array_key_exists('idtyp', $claims) && $claims['idtyp'] !== 'user') {
            throw self::invalid("The access token is not a person's token (idtyp).");
        }
        if ($this->tenants !== null && !in_array($tenantId, $this->tenants, true)) {
            throw new RanteAppsException('tenant_not_allowed', 'This tenant may not use this app.');
        }
        $scopes = is_string($claims['scp'] ?? null) ? array_values(array_filter(explode(' ', $claims['scp']), static fn (string $s): bool => $s !== '')) : [];
        $missing = array_values(array_diff($this->requiredScopes, $scopes));
        if ($missing !== []) {
            throw new RanteAppsException(
                'insufficient_scope',
                'The access token lacks the scope' . (count($missing) > 1 ? 's ' : ' ') . implode(', ', $missing) . '.',
                $this->requiredScopes,
            );
        }
        $roles = [];
        if (is_array($claims['roles'] ?? null)) {
            foreach ($claims['roles'] as $role) {
                if (is_string($role)) {
                    $roles[] = $role;
                }
            }
        }
        $text = static fn (string $name): ?string => is_string($claims[$name] ?? null) ? $claims[$name] : null;
        return new RanteAppPrincipal(
            userId: strtolower($oid),
            tenantId: $tenantId,
            subject: $text('sub'),
            name: $text('name'),
            username: $text('preferred_username'),
            email: $text('email'),
            appId: $this->clientId,
            authorizedParty: $text('azp'),
            scopes: $scopes,
            roles: $roles,
            issuedAt: is_int($iat) || is_float($iat) ? (new \DateTimeImmutable('@' . (int) $iat)) : null,
            expiresAt: new \DateTimeImmutable('@' . (int) $exp),
            issuer: $iss,
            claims: $claims,
        );
    }

    private function audienceMatches(mixed $aud): bool
    {
        $values = is_array($aud) ? $aud : [$aud];
        foreach ($values as $value) {
            if (is_string($value) && in_array(strtolower($value), $this->audiences, true)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------------------------------- keys

    /** @return array<string, mixed> the JWK */
    private function signingKey(string $kid): array
    {
        $now = time();
        if ($this->snapshot === null && $this->cache !== null) {
            $cached = $this->cache->get($this->cacheKey);
            if (is_array($cached) && isset($cached['keys'], $cached['fetchedAt'], $cached['jwksUri'])) {
                $this->snapshot = $cached;
            }
        }
        $snapshot = $this->snapshot;
        $stale = $snapshot === null || $now - $snapshot['fetchedAt'] > $this->jwksMaxAge;
        if ($stale || (!isset($snapshot['keys'][$kid]) && $now - $snapshot['fetchedAt'] >= $this->jwksCooldown)) {
            $snapshot = $this->fetchKeys($snapshot['jwksUri'] ?? null);
            $this->snapshot = $snapshot;
            $this->cache?->set($this->cacheKey, $snapshot, $this->jwksMaxAge);
        }
        if (!isset($snapshot['keys'][$kid])) {
            throw self::invalid('No signing key of Rante Login matches the access token.');
        }
        return $snapshot['keys'][$kid];
    }

    /** @return array{keys: array<string, array<string, mixed>>, fetchedAt: int, jwksUri: string} */
    private function fetchKeys(?string $jwksUri): array
    {
        if ($jwksUri === null) {
            $metadata = $this->getJson(
                $this->authority . '/common/v2.0/.well-known/openid-configuration',
                'discovery_failed',
                "Rante Login's OpenID configuration",
            );
            if (($metadata['issuer'] ?? null) !== $this->authority . '/common/v2.0') {
                throw new RanteAppsException('discovery_failed', "Rante Login's OpenID configuration names another issuer.");
            }
            $uri = $metadata['jwks_uri'] ?? null;
            $parts = is_string($uri) ? parse_url($uri) : false;
            $scheme = is_array($parts) ? strtolower($parts['scheme'] ?? '') : '';
            $host = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
            if (!($scheme === 'https' || ($scheme === 'http' && in_array($host, self::LOCAL_HOSTS, true)))) {
                throw new RanteAppsException('discovery_failed', "Rante Login's OpenID configuration has no valid https jwks_uri.");
            }
            $jwksUri = $uri;
        }
        $set = $this->getJson($jwksUri, 'network_error', "Rante Login's signing keys");
        $keys = [];
        foreach (is_array($set['keys'] ?? null) ? $set['keys'] : [] as $jwk) {
            if (!is_array($jwk) || !is_string($jwk['kid'] ?? null) || $jwk['kid'] === '') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            $keys[$jwk['kid']] ??= $jwk;
        }
        return ['keys' => $keys, 'fetchedAt' => time(), 'jwksUri' => $jwksUri];
    }

    /** @return array<string, mixed> */
    private function getJson(string $url, string $failureCode, string $what): array
    {
        try {
            $response = $this->http->get($url);
        } catch (\RuntimeException $e) {
            throw new RanteAppsException('network_error', $what . ' could not be fetched.', [], $e);
        }
        if ($response->status !== 200) {
            throw new RanteAppsException($failureCode, $what . ' answered ' . $response->status . '.');
        }
        $value = $response->json();
        if ($value === null) {
            throw new RanteAppsException($failureCode, $what . ' is not a JSON object.');
        }
        return $value;
    }

    // ------------------------------------------------------------------------------------------- helpers

    private static function invalid(string $message, ?\Throwable $previous = null): RanteAppsException
    {
        return new RanteAppsException('invalid_token', $message, [], $previous);
    }

    private static function config(string $message): RanteAppsException
    {
        return new RanteAppsException('invalid_configuration', $message);
    }

    private static function normalizeAuthority(string $value): string
    {
        $parts = parse_url($value);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw self::config('authority must be an absolute URL such as https://login.rante.com.');
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        if ($scheme !== 'https' && !($scheme === 'http' && in_array($host, self::LOCAL_HOSTS, true))) {
            throw self::config('authority must use https (http is accepted only for localhost, for tests).');
        }
        if ((isset($parts['path']) && $parts['path'] !== '/') || isset($parts['query']) || isset($parts['fragment']) || isset($parts['user'])) {
            throw self::config('authority is an origin only, such as https://login.rante.com.');
        }
        return $scheme . '://' . $host . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
