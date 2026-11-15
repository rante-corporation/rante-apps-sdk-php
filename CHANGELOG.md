# Changelog

## 0.1.0 (unreleased)

- `RanteAppTokenVerifier`: checks Rante app access tokens as described in docs/tokens.md of rante-apps-sdk
  (signature from Rante Login's JWKS with key rotation and a refetch cooldown, `aud`, per-tenant `iss`,
  `exp` / `nbf` / `iat` with clock skew, `oid`, `idtyp`), with optional tenant and scope requirements and an optional
  PSR-16 key cache.
- `RanteAppPrincipal`, `RanteAppsException` (with `status()` and `wwwAuthenticate()`), `BearerToken`,
  `RanteApps::FRAME_ANCESTORS`, a cURL HTTP client.
- Passes the shared conformance cases (conformance/tokens.json). PHP 8.2+, on firebase/php-jwt 7.
- Example external app on PHP's built-in server.
