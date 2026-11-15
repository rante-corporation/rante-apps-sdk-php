<?php

declare(strict_types=1);

namespace Rante\Apps;

/** Every failure, with a stable code (docs/tokens.md) and the HTTP status to answer with. */
final class RanteAppsException extends \RuntimeException
{
    private const STATUS = [
        'missing_token' => 401,
        'invalid_token' => 401,
        'token_expired' => 401,
        'tenant_not_allowed' => 403,
        'insufficient_scope' => 403,
        'discovery_failed' => 503,
        'network_error' => 503,
        'invalid_configuration' => 500,
    ];

    /**
     * @param string $errorCode missing_token, invalid_token, token_expired, tenant_not_allowed, insufficient_scope,
     *   discovery_failed, network_error or invalid_configuration
     * @param list<string> $requiredScopes the scopes the verifier requires (for insufficient_scope)
     */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly array $requiredScopes = [],
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /** The HTTP status to answer with. */
    public function status(): int
    {
        return self::STATUS[$this->errorCode] ?? 500;
    }

    /** The WWW-Authenticate header value for this error (RFC 6750), or null. */
    public function wwwAuthenticate(): ?string
    {
        return match ($this->errorCode) {
            'missing_token' => 'Bearer',
            'invalid_token', 'token_expired' => 'Bearer error="invalid_token", error_description="' . self::headerText($this->getMessage()) . '"',
            'insufficient_scope' => 'Bearer error="insufficient_scope", scope="' . self::headerText(implode(' ', $this->requiredScopes)) . '"',
            default => null,
        };
    }

    private static function headerText(string $value): string
    {
        $value = str_replace(['"', '\\'], "'", $value);
        return (string) preg_replace('/[^\x20-\x7e]/', ' ', $value);
    }
}
