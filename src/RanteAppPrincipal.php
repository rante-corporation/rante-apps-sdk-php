<?php

declare(strict_types=1);

namespace Rante\Apps;

/** Who a verified token is for. */
final class RanteAppPrincipal
{
    /**
     * @param string $userId the person's object ID in the tenant (oid)
     * @param string $tenantId the tenant (tid)
     * @param string|null $subject the person's subject for this app (sub): stable, different for every app
     * @param string|null $username preferred_username
     * @param string $appId your client ID
     * @param string|null $authorizedParty azp: the client that asked for the token on the person's behalf
     * @param list<string> $scopes the permissions the tenant granted (scp)
     * @param list<string> $roles
     * @param array<string, mixed> $claims every claim of the token
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $tenantId,
        public readonly ?string $subject,
        public readonly ?string $name,
        public readonly ?string $username,
        public readonly ?string $email,
        public readonly string $appId,
        public readonly ?string $authorizedParty,
        public readonly array $scopes,
        public readonly array $roles,
        public readonly ?\DateTimeImmutable $issuedAt,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly string $issuer,
        public readonly array $claims,
    ) {
    }
}
