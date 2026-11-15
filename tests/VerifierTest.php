<?php

declare(strict_types=1);

namespace Rante\Apps\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Rante\Apps\BearerToken;
use Rante\Apps\RanteApps;
use Rante\Apps\RanteAppsException;
use Rante\Apps\RanteAppTokenVerifier;

final class VerifierTest extends TestCase
{
    private LocalLogin $login;
    /** @var array<string, mixed> */
    private array $doc;

    protected function setUp(): void
    {
        $this->login = new LocalLogin();
        $this->doc = LocalLogin::cases();
    }

    /** @param array<string, mixed> $options */
    private function verifier(array $options = []): RanteAppTokenVerifier
    {
        return new RanteAppTokenVerifier($this->doc['clientId'], ...($options + ['authority' => LocalLogin::ORIGIN, 'httpClient' => $this->login]));
    }

    /** @param array<string, mixed>|null $claims */
    private function token(?array $claims = null, ?string $sign = null): string
    {
        $case = [];
        if ($claims !== null) {
            $case['claims'] = $claims;
        }
        if ($sign !== null) {
            $case['sign'] = $sign;
        }
        return $this->login->buildToken($this->doc, $case, time());
    }

    private function assertCode(string $code, callable $action): void
    {
        try {
            $action();
            $this->fail('expected ' . $code);
        } catch (RanteAppsException $e) {
            $this->assertSame($code, $e->errorCode, $e->getMessage());
        }
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function badOptions(): array
    {
        return [
            'client id' => [['clientId' => 'contoso-app']],
            'http authority' => [['authority' => 'http://login.example.com']],
            'authority path' => [['authority' => 'https://login.example.com/tenant']],
            'HS256' => [['algorithms' => ['HS256']]],
            'no algorithms' => [['algorithms' => []]],
            'tenant' => [['tenants' => ['contoso']]],
            'clock skew' => [['clockSkew' => -1]],
            'scope' => [['requiredScopes' => ['two words']]],
        ];
    }

    /** @param array<string, mixed> $options */
    #[DataProvider('badOptions')]
    public function testTheOptionsAreChecked(array $options): void
    {
        $clientId = $options['clientId'] ?? '3f2b8c1e-7d4a-4e9b-a6c5-1d2e3f4a5b6c';
        unset($options['clientId']);
        $this->assertCode('invalid_configuration', static fn () => new RanteAppTokenVerifier($clientId, ...$options));
    }

    public function testDefaultsAreNormalized(): void
    {
        $this->assertSame($this->doc['clientId'], (new RanteAppTokenVerifier(strtoupper($this->doc['clientId'])))->clientId());
        $this->assertSame('https://login.rante.com', (new RanteAppTokenVerifier($this->doc['clientId']))->authority());
        $this->assertSame('http://localhost:8080', (new RanteAppTokenVerifier($this->doc['clientId'], authority: 'http://localhost:8080/'))->authority());
        $this->assertSame('frame-ancestors https://portal.rante.com', RanteApps::FRAME_ANCESTORS);
    }

    public function testBearerTokensAreRead(): void
    {
        $this->assertSame('abc.def.ghi', BearerToken::fromAuthorizationHeader('Bearer abc.def.ghi'));
        $this->assertSame('abc.def-_~+/=', BearerToken::fromAuthorizationHeader('bearer   abc.def-_~+/='));
        foreach ([null, '', 'Basic dXNlcjpwYXNz', 'Bearer', 'Bearer a b', 'Bearer a,b'] as $value) {
            $this->assertNull(BearerToken::fromAuthorizationHeader($value), (string) $value);
        }
    }

    public function testErrorsCarryStatusAndWwwAuthenticate(): void
    {
        $this->assertSame('Bearer', (new RanteAppsException('missing_token', 'x'))->wwwAuthenticate());
        $this->assertSame('Bearer error="invalid_token", error_description="The \'token\' expired."', (new RanteAppsException('token_expired', 'The "token" expired.'))->wwwAuthenticate());
        $scope = new RanteAppsException('insufficient_scope', 'x', ['user.read', 'auth.token']);
        $this->assertSame(403, $scope->status());
        $this->assertSame('Bearer error="insufficient_scope", scope="user.read auth.token"', $scope->wwwAuthenticate());
        $this->assertNull((new RanteAppsException('tenant_not_allowed', 'x'))->wwwAuthenticate());
        $this->assertSame(503, (new RanteAppsException('network_error', 'x'))->status());
    }

    public function testTheConfigurationAndKeysAreFetchedOnce(): void
    {
        $verifier = $this->verifier();
        for ($i = 0; $i < 4; $i++) {
            $verifier->verify($this->token());
        }
        $this->assertSame(1, $this->login->discoveryCount);
        $this->assertSame(1, $this->login->jwksCount);
    }

    public function testACacheSharesTheKeysBetweenVerifiers(): void
    {
        $cache = new ArrayCache();
        $this->verifier(['cache' => $cache])->verify($this->token());
        $this->verifier(['cache' => $cache])->verify($this->token());
        $this->assertSame(1, $this->login->jwksCount);
    }

    public function testAnUnknownKidDoesNotRefetchDuringTheCooldown(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->token());
        for ($i = 0; $i < 3; $i++) {
            $token = $this->login->buildToken($this->doc, ['header' => ['kid' => 'made-up']], time());
            $this->assertCode('invalid_token', static fn () => $verifier->verify($token));
        }
        $this->assertSame(1, $this->login->jwksCount);
    }

    public function testANewKeyIsPickedUp(): void
    {
        $verifier = $this->verifier(['jwksCooldown' => 0]);
        $verifier->verify($this->token());
        $this->login->publishSecondKey();
        $this->assertSame($this->doc['tenantId'], $verifier->verify($this->token(null, 'key-2'))->tenantId);
        $this->assertSame(2, $this->login->jwksCount);
    }

    public function testEs256IsAcceptedWhenAllowed(): void
    {
        $verifier = $this->verifier(['algorithms' => ['RS256', 'ES256']]);
        $this->assertSame($this->doc['userId'], $verifier->verify($this->token(null, 'es256'))->userId);
    }

    public function testThePrincipalCarriesTheClaims(): void
    {
        $p = $this->verifier()->verify($this->token(['roles' => ['Reader', 7], 'email' => 'ada@example.com']));
        $this->assertSame($this->doc['clientId'], $p->appId);
        $this->assertSame(['Reader'], $p->roles);
        $this->assertSame('ada@example.com', $p->email);
        $this->assertGreaterThan(new \DateTimeImmutable(), $p->expiresAt);
        $this->assertSame('2.0', $p->claims['ver']);
    }

    public function testDiscoveryProblemsAreReported(): void
    {
        $token = $this->token();
        $this->login->mode = 'not-found';
        $this->assertCode('discovery_failed', fn () => $this->verifier()->verify($token));
        $this->login->mode = 'other-issuer';
        $this->assertCode('discovery_failed', fn () => $this->verifier()->verify($token));
        $this->login->mode = 'down';
        $this->assertCode('network_error', fn () => $this->verifier()->verify($token));
    }

    public function testAFailedFetchIsRetried(): void
    {
        $verifier = $this->verifier();
        $token = $this->token();
        $this->login->mode = 'down';
        $this->assertCode('network_error', static fn () => $verifier->verify($token));
        $this->login->mode = 'ok';
        $this->assertSame($this->doc['tenantId'], $verifier->verify($token)->tenantId);
    }
}
