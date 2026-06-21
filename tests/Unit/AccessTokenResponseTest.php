<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Deroy2112\LaravelSynologySso\Exceptions\MissingPkceVerifierException;
use Deroy2112\LaravelSynologySso\Tests\Support\TestableSynologyDriver;
use Deroy2112\LaravelSynologySso\Tests\TestCase;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;

/**
 * The token exchange depends on a PKCE verifier stashed in the session during
 * the redirect. If it is missing (expired session, replayed callback) the
 * driver must fail with a typed, catchable exception rather than a bare
 * RuntimeException.
 */
class AccessTokenResponseTest extends TestCase
{
    #[Test]
    public function it_throws_a_typed_exception_when_the_pkce_verifier_is_missing(): void
    {
        $driver = new TestableSynologyDriver(
            Request::create('/', 'GET'),
            'test-client-id',
            'test-client-secret',
            'https://app.example.com/callback'
        );

        $this->expectException(MissingPkceVerifierException::class);

        $driver->callGetAccessTokenResponse('authorization-code');
    }
}
