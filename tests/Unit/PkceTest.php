<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Orchestra\Testbench\TestCase;
use Deroy2112\LaravelSynologySso\SynologySocialiteDriver;
use Illuminate\Http\Request;
use Laravel\Socialite\Two\User;

class PkceTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \Laravel\Socialite\SocialiteServiceProvider::class,
            \Deroy2112\LaravelSynologySso\SynologySsoServiceProvider::class,
        ];
    }

    /** @test */
    public function it_generates_valid_pkce_verifier_and_challenge()
    {
        // Use reflection to access protected method
        $driver = $this->createDriver();
        $reflection = new \ReflectionClass($driver);
        $method = $reflection->getMethod('generatePkce');
        $method->setAccessible(true);

        $pkce = $method->invoke($driver);

        // Verifier should be 64 characters (32 bytes hex-encoded)
        $this->assertEquals(64, strlen($pkce['verifier']));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $pkce['verifier']);

        // Challenge should be base64url-encoded SHA-256 hash (43 characters)
        $this->assertEquals(43, strlen($pkce['challenge']));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $pkce['challenge']);
    }

    /** @test */
    public function it_generates_unique_pkce_values()
    {
        $driver = $this->createDriver();
        $reflection = new \ReflectionClass($driver);
        $method = $reflection->getMethod('generatePkce');
        $method->setAccessible(true);

        $pkce1 = $method->invoke($driver);
        $pkce2 = $method->invoke($driver);

        // Each generation should produce unique values
        $this->assertNotEquals($pkce1['verifier'], $pkce2['verifier']);
        $this->assertNotEquals($pkce1['challenge'], $pkce2['challenge']);
    }

    /** @test */
    public function it_creates_valid_sha256_challenge_from_verifier()
    {
        $driver = $this->createDriver();
        $reflection = new \ReflectionClass($driver);
        $method = $reflection->getMethod('generatePkce');
        $method->setAccessible(true);

        $pkce = $method->invoke($driver);

        // Manually compute expected challenge
        $expectedChallenge = rtrim(
            strtr(base64_encode(hash('sha256', $pkce['verifier'], true)), '+/', '-_'),
            '='
        );

        $this->assertEquals($expectedChallenge, $pkce['challenge']);
    }

    /**
     * Create a minimal driver instance for testing.
     */
    protected function createDriver(): SynologySocialiteDriver
    {
        $request = Request::create('/', 'GET');

        config([
            'synology-sso.host' => 'https://sso.example.com',
            'synology-sso.client_id' => 'test-client-id',
            'synology-sso.client_secret' => 'test-secret',
            'synology-sso.redirect_uri' => 'https://app.example.com/callback',
        ]);

        return new SynologySocialiteDriver(
            $request,
            'test-client-id',
            'test-secret',
            'https://app.example.com/callback'
        );
    }
}
