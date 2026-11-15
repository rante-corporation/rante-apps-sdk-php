<?php

declare(strict_types=1);

namespace Rante\Apps\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Rante\Apps\RanteAppsException;
use Rante\Apps\RanteAppTokenVerifier;

/**
 * Runs conformance/tokens.json (a copy of rante-apps-sdk/conformance/tokens.json): the cases every Rante Apps server
 * SDK passes, in every language.
 */
final class ConformanceTest extends TestCase
{
    private static ?LocalLogin $login = null;
    private static ?RanteAppTokenVerifier $shared = null;

    public static function setUpBeforeClass(): void
    {
        self::$login = new LocalLogin();
        self::$shared = new RanteAppTokenVerifier(LocalLogin::cases()['clientId'], authority: LocalLogin::ORIGIN, httpClient: self::$login);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function cases(): array
    {
        $out = [];
        foreach (LocalLogin::cases()['cases'] as $case) {
            $out[$case['name']] = [$case];
        }
        return $out;
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testCase(array $case): void
    {
        $doc = LocalLogin::cases();
        $now = time();
        $verifier = self::$shared;
        if (isset($case['options'])) {
            $options = LocalLogin::resolve($doc, $case['options'], $now);
            $verifier = new RanteAppTokenVerifier(
                $doc['clientId'],
                tenants: $options['tenants'] ?? [],
                requiredScopes: $options['requiredScopes'] ?? [],
                authority: LocalLogin::ORIGIN,
                httpClient: self::$login,
            );
        }
        $token = self::$login->buildToken($doc, $case, $now);
        if ($case['expect'] === null) {
            $principal = $verifier->verify($token);
            foreach (LocalLogin::resolve($doc, $case['principal'] ?? [], $now) as $field => $value) {
                $this->assertSame($value, $principal->{$field}, $field);
            }
            return;
        }
        try {
            $verifier->verify($token);
            $this->fail('expected ' . $case['expect']);
        } catch (RanteAppsException $e) {
            $this->assertSame($case['expect'], $e->errorCode, $e->getMessage());
        }
    }
}
