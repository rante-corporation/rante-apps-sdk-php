<?php

declare(strict_types=1);

namespace Rante\Apps;

/** Reads bearer tokens from Authorization headers. */
final class BearerToken
{
    /** The token of an Authorization header value ("Bearer <token>"), or null when there is none. */
    public static function fromAuthorizationHeader(?string $header): ?string
    {
        if ($header === null) {
            return null;
        }
        return preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*)$/i', trim($header), $m) === 1 ? $m[1] : null;
    }
}
