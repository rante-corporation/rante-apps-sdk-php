<?php

declare(strict_types=1);

namespace Rante\Apps\Http;

/**
 * The GET requests the SDK makes to Rante Login. CurlHttpClient is the default; implement this to use a proxy or
 * another HTTP library. Implementations must not follow redirects, and throw \RuntimeException when the server can't
 * be reached.
 */
interface HttpClient
{
    public function get(string $url): HttpResponse;
}
