# Rante Apps server SDK for PHP

Check, on your server, the access tokens your Rante app's frontend gets from
[`Rante.getAccessToken()`](https://github.com/rante-corporation/rante-apps-sdk/tree/main/packages/sdk), and find out
who and which tenant each request is for. Built on [firebase/php-jwt](https://github.com/firebase/php-jwt).
PHP 8.2 or later, with ext-curl and ext-openssl.

What a token contains and what is checked: [docs/tokens.md](https://github.com/rante-corporation/rante-apps-sdk/blob/main/docs/tokens.md).
The same checks, error codes and test cases exist for [Node.js](https://github.com/rante-corporation/rante-apps-sdk-node),
[Python](https://github.com/rante-corporation/rante-apps-sdk-python), [.NET](https://github.com/rante-corporation/rante-apps-sdk-dotnet),
[Java](https://github.com/rante-corporation/rante-apps-sdk-java) and [Go](https://github.com/rante-corporation/rante-apps-sdk-go).

Status: 0.1.0. Rante's hosting of apps is being built to this design; tokens are issued once it is live.

## Install

From GitHub (not on Packagist yet). In your `composer.json`:

```json
{
    "repositories": [{ "type": "vcs", "url": "https://github.com/rante-corporation/rante-apps-sdk-php" }],
    "require": { "rante/apps-sdk": "dev-main" }
}
```

## Use

```php
use Rante\Apps\BearerToken;
use Rante\Apps\RanteAppsException;
use Rante\Apps\RanteAppTokenVerifier;

// Give it a PSR-16 cache so that PHP requests share Rante Login's signing keys.
$verifier = new RanteAppTokenVerifier(getenv('RANTE_CLIENT_ID'), cache: $psr16Cache);

try {
    $principal = $verifier->verify(BearerToken::fromAuthorizationHeader($_SERVER['HTTP_AUTHORIZATION'] ?? null));
    $principal->userId;   // the person (oid)
    $principal->tenantId; // the customer's tenant (tid)
    $principal->scopes;   // what the tenant granted, e.g. ['user.read', 'tenant.read', 'auth.token']
} catch (RanteAppsException $error) {
    http_response_code($error->status());
    if ($error->wwwAuthenticate() !== null) {
        header('WWW-Authenticate: ' . $error->wwwAuthenticate());
    }
}
```

Your pages should send `Content-Security-Policy: frame-ancestors https://portal.rante.com`
(`RanteApps::FRAME_ANCESTORS`) so that only Rante can frame them.

## Options

Named constructor arguments:

| Argument | Default | |
|---|---|---|
| `clientId` | (required, first) | Your app's Application (client) ID. |
| `tenants` | any tenant | Accept tokens of these tenants only (`tenant_not_allowed` otherwise). |
| `requiredScopes` | none | Scopes every token must have (`insufficient_scope` otherwise). |
| `extraAudiences` | none | Audiences accepted besides the client ID, such as `api://{clientId}`. |
| `authority` | `https://login.rante.com` | http is accepted for localhost only, for tests. |
| `clockSkew` | `60` | Seconds of clock difference tolerated for `exp`, `nbf` and `iat`. |
| `algorithms` | `['RS256']` | `RS256` and `ES256` are supported. |
| `timeout` | `5.0` | Seconds for each request to Rante Login. |
| `jwksCooldown` | `30` | Minimum seconds between two key fetches (an unknown `kid` triggers one). |
| `jwksMaxAge` | `600` | Seconds fetched keys are used before they are fetched again. |
| `httpClient` | cURL | A `Rante\Apps\Http\HttpClient`, for proxies or tests. |
| `cache` | none | A PSR-16 cache for the keys, shared between requests. |

## The principal

`RanteAppPrincipal` has read-only properties: `userId` (oid), `tenantId` (tid), `subject` (sub: stable, different for
every app), `name`, `username` (preferred_username), `email`, `appId` (your client ID), `authorizedParty` (azp),
`scopes` (from scp), `roles`, `issuedAt`, `expiresAt` (`DateTimeImmutable`), `issuer` and `claims`.

## Errors

`verify` throws `RanteAppsException` with `errorCode` one of `missing_token`, `invalid_token`, `token_expired` (401),
`tenant_not_allowed`, `insufficient_scope` (403), `discovery_failed`, `network_error` (503) or
`invalid_configuration` (500). `status()` is that HTTP status and `wwwAuthenticate()` the header value to send with
it (or `null`).

## Example

[examples/builtin-server](examples/builtin-server) is a complete external app on PHP's built-in server: a page that
asks Rante for a token and an `/api/me` endpoint that checks it.

```bash
composer install
RANTE_CLIENT_ID=<your-app-id> php -S localhost:3000 -t examples/builtin-server/public examples/builtin-server/public/index.php
```

Rante opens external apps from an `https://` address, so register the server behind one in
[manifest.json](examples/builtin-server/manifest.json).

## Tests

```bash
composer install
composer test
```

`tests/conformance/tokens.json` is a copy of
[conformance/tokens.json](https://github.com/rante-corporation/rante-apps-sdk/blob/main/conformance/tokens.json): the
cases every server SDK passes. The tests sign them with keys generated for the run and answer the key requests in
process; nothing leaves the machine.

## License

[MIT](LICENSE). Report security problems privately through this repository's Security tab.
