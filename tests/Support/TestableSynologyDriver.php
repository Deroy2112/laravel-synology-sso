<?php

namespace Deroy2112\LaravelSynologySso\Tests\Support;

use Deroy2112\LaravelSynologySso\SynologySocialiteDriver;

/**
 * Test-only subclass that exposes the protected ID-token verification routine.
 *
 * ID-token verification is the security boundary of the driver but is protected
 * to follow Socialite's provider conventions. Exercising it through the full
 * user() flow would require mocking three HTTP endpoints plus session state;
 * exposing it directly keeps the security tests focused and deterministic.
 */
final class TestableSynologyDriver extends SynologySocialiteDriver
{
    /**
     * @return array<string, mixed>
     */
    public function callVerifyIdToken(string $idToken): array
    {
        return $this->verifyIdToken($idToken);
    }

    /**
     * @return array<string, mixed>
     */
    public function callHttpClientOptions(): array
    {
        return $this->httpClientOptions();
    }
}
