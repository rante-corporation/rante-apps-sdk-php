<?php

// An external Rante app on PHP's built-in server: the page gets an access token from Rante and calls /api/me, which
// checks it with the Rante Apps server SDK.
//   composer install            (in the repository root)
//   RANTE_CLIENT_ID=<your app's client ID> php -S localhost:3000 -t examples/builtin-server/public examples/builtin-server/public/index.php

declare(strict_types=1);

require __DIR__ . '/../../../vendor/autoload.php';

use Rante\Apps\BearerToken;
use Rante\Apps\RanteApps;
use Rante\Apps\RanteAppsException;
use Rante\Apps\RanteAppTokenVerifier;

$clientId = getenv('RANTE_CLIENT_ID');
if ($clientId === false || $clientId === '') {
    http_response_code(500);
    exit("Set RANTE_CLIENT_ID to your app's Application (client) ID.");
}
$tenants = getenv('RANTE_TENANTS');

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$files = ['/app.js' => 'text/javascript', '/style.css' => 'text/css', '/rante-sdk.js' => 'text/javascript'];

if ($path === '/') {
    // Only Rante may frame the app; everything else loads from this server.
    header('Content-Security-Policy: ' . RanteApps::FRAME_ANCESTORS . "; default-src 'self'; object-src 'none'; base-uri 'none'");
    header('Content-Type: text/html; charset=utf-8');
    echo str_replace('__RANTE_CLIENT_ID__', strtolower($clientId), (string) file_get_contents(__DIR__ . '/index.html'));
    return;
}

if (isset($files[$path])) {
    header('Content-Type: ' . $files[$path] . '; charset=utf-8');
    readfile(__DIR__ . $path);
    return;
}

if ($path === '/api/me') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    try {
        // Rante Login's keys are kept in memory for this request only; give the verifier a PSR-16 cache
        // (APCu, Redis, files...) so that requests share them.
        $verifier = new RanteAppTokenVerifier($clientId, tenants: $tenants ? array_map('trim', explode(',', $tenants)) : []);
        $p = $verifier->verify(BearerToken::fromAuthorizationHeader($_SERVER['HTTP_AUTHORIZATION'] ?? null));
        echo json_encode([
            'userId' => $p->userId,
            'tenantId' => $p->tenantId,
            'name' => $p->name,
            'username' => $p->username,
            'scopes' => $p->scopes,
            'expiresAt' => $p->expiresAt->format(DATE_ATOM),
        ]);
    } catch (RanteAppsException $error) {
        http_response_code($error->status());
        if ($error->wwwAuthenticate() !== null) {
            header('WWW-Authenticate: ' . $error->wwwAuthenticate());
        }
        echo json_encode(['error' => $error->errorCode, 'message' => $error->getMessage()]);
    }
    return;
}

http_response_code(404);
echo 'Not found';
