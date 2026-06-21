<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Deroy2112\LaravelSynologySso\Exceptions\InvalidIdTokenException;
use Deroy2112\LaravelSynologySso\Tests\Support\RsaTestKey;
use Deroy2112\LaravelSynologySso\Tests\Support\TestableSynologyDriver;
use Deroy2112\LaravelSynologySso\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\Test;

/**
 * Regression net for the security boundary of the driver: RS256 signature
 * verification against the JWKS plus issuer/audience/expiry/subject claim
 * checks. The OIDC discovery document and JWKS are pre-seeded into the cache
 * so verification runs against a real signed JWT without any network access.
 */
class IdTokenVerificationTest extends TestCase
{
    private const HOST = 'https://sso.example.com/webman/sso';
    private const ISSUER = 'https://sso.example.com/webman/sso';
    private const JWKS_URI = 'https://sso.example.com/webman/sso/oauth/jwks';
    private const CLIENT_ID = 'test-client-id';

    private RsaTestKey $key;
    private TestableSynologyDriver $driver;

    protected function setUp(): void
    {
        parent::setUp();

        $this->key = new RsaTestKey();

        Cache::put('synology_sso_oidc_config_' . md5(self::HOST), [
            'issuer' => self::ISSUER,
            'jwks_uri' => self::JWKS_URI,
            'authorization_endpoint' => self::HOST . '/authorize',
            'token_endpoint' => self::HOST . '/token',
            'userinfo_endpoint' => self::HOST . '/userinfo',
        ], 3600);

        Cache::put('synology_sso_jwks_' . md5(self::JWKS_URI), $this->key->jwks, 3600);

        $this->driver = new TestableSynologyDriver(
            Request::create('/', 'GET'),
            self::CLIENT_ID,
            'test-client-secret',
            'https://app.example.com/callback'
        );
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
            'exp' => time() + 3600,
            'iat' => time() - 10,
            'sub' => 'synology-user-123',
            'email' => 'user@example.com',
        ], $overrides);
    }

    #[Test]
    public function it_accepts_a_valid_signed_id_token(): void
    {
        $token = $this->key->sign($this->claims());

        $claims = $this->driver->callVerifyIdToken($token);

        $this->assertSame('synology-user-123', $claims['sub']);
        $this->assertSame('user@example.com', $claims['email']);
        $this->assertSame(self::ISSUER, $claims['iss']);
    }

    #[Test]
    public function it_rejects_a_token_with_the_wrong_issuer(): void
    {
        $token = $this->key->sign($this->claims(['iss' => 'https://evil.example.com']));

        $this->expectException(InvalidIdTokenException::class);
        $this->expectExceptionMessage('Invalid issuer');

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_a_token_issued_for_a_different_audience(): void
    {
        $token = $this->key->sign($this->claims(['aud' => 'some-other-client']));

        $this->expectException(InvalidIdTokenException::class);
        $this->expectExceptionMessage('Invalid audience');

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_a_token_without_a_subject_claim(): void
    {
        $claims = $this->claims();
        unset($claims['sub']);
        $token = $this->key->sign($claims);

        $this->expectException(InvalidIdTokenException::class);
        $this->expectExceptionMessage('Missing subject claim');

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_an_expired_token(): void
    {
        $token = $this->key->sign($this->claims([
            'iat' => time() - 7200,
            'exp' => time() - 3600,
        ]));

        $this->expectException(InvalidIdTokenException::class);

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_a_token_issued_in_the_future(): void
    {
        $token = $this->key->sign($this->claims(['iat' => time() + 3600]));

        $this->expectException(InvalidIdTokenException::class);

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_accepts_a_token_whose_audience_array_contains_this_client(): void
    {
        $token = $this->key->sign($this->claims([
            'aud' => ['some-other-client', self::CLIENT_ID],
        ]));

        $claims = $this->driver->callVerifyIdToken($token);

        $this->assertSame('synology-user-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_a_token_whose_audience_array_excludes_this_client(): void
    {
        $token = $this->key->sign($this->claims([
            'aud' => ['client-a', 'client-b'],
        ]));

        $this->expectException(InvalidIdTokenException::class);
        $this->expectExceptionMessage('Invalid audience');

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_a_token_with_an_authorized_party_for_another_client(): void
    {
        $token = $this->key->sign($this->claims([
            'aud' => self::CLIENT_ID,
            'azp' => 'some-other-client',
        ]));

        $this->expectException(InvalidIdTokenException::class);
        $this->expectExceptionMessage('Invalid authorized party');

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_accepts_a_token_issued_slightly_in_the_future_within_leeway(): void
    {
        $token = $this->key->sign($this->claims(['iat' => time() + 30]));

        $claims = $this->driver->callVerifyIdToken($token);

        $this->assertSame('synology-user-123', $claims['sub']);
    }

    #[Test]
    public function it_accepts_a_token_that_just_expired_within_leeway(): void
    {
        $token = $this->key->sign($this->claims([
            'iat' => time() - 200,
            'exp' => time() - 30,
        ]));

        $claims = $this->driver->callVerifyIdToken($token);

        $this->assertSame('synology-user-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_a_token_signed_by_an_unknown_key(): void
    {
        $foreignKey = new RsaTestKey('attacker-key');
        $token = $foreignKey->sign($this->claims());

        $this->expectException(InvalidIdTokenException::class);

        $this->driver->callVerifyIdToken($token);
    }

    #[Test]
    public function it_rejects_a_tampered_token(): void
    {
        $token = $this->key->sign($this->claims());
        $tampered = substr($token, 0, -4) . 'AAAA';

        $this->expectException(InvalidIdTokenException::class);

        $this->driver->callVerifyIdToken($tampered);
    }
}
