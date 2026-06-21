<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Deroy2112\LaravelSynologySso\Tests\Support\TestableSynologyDriver;
use Deroy2112\LaravelSynologySso\Tests\TestCase;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;

/**
 * Guards that the configured TLS setting actually reaches the HTTP client.
 * Before consolidation the driver created bare Guzzle clients and the
 * verify_ssl option was silently ignored.
 */
class HttpClientConfigTest extends TestCase
{
    private function makeDriver(): TestableSynologyDriver
    {
        return new TestableSynologyDriver(
            Request::create('/', 'GET'),
            'test-client-id',
            'test-client-secret',
            'https://app.example.com/callback'
        );
    }

    #[Test]
    public function it_verifies_ssl_certificates_by_default(): void
    {
        config(['synology-sso.verify_ssl' => true]);

        $options = $this->makeDriver()->callHttpClientOptions();

        $this->assertTrue($options['verify']);
    }

    #[Test]
    public function it_propagates_disabled_ssl_verification_from_config(): void
    {
        config(['synology-sso.verify_ssl' => false]);

        $options = $this->makeDriver()->callHttpClientOptions();

        $this->assertFalse($options['verify']);
    }
}
