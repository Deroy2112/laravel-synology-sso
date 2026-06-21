<?php

namespace Deroy2112\LaravelSynologySso\Tests\Support;

use Firebase\JWT\JWT;
use RuntimeException;

/**
 * Generates an ephemeral RSA key pair for signing test ID tokens and exposes
 * the matching JWKS, so ID-token verification can be exercised end-to-end
 * without contacting a real Synology SSO server.
 */
final class RsaTestKey
{
    private const KEY_BITS = 2048;

    public readonly string $privatePem;

    /** @var array{keys: list<array<string, string>>} */
    public readonly array $jwks;

    public function __construct(private readonly string $kid = 'test-key')
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => self::KEY_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new RuntimeException('Failed to generate RSA test key pair');
        }

        if (openssl_pkey_export($resource, $privatePem) === false) {
            throw new RuntimeException('Failed to export RSA private key');
        }

        $details = openssl_pkey_get_details($resource);

        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('Failed to read RSA key details');
        }

        $this->privatePem = $privatePem;
        $this->jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $this->kid,
                    'n' => self::base64Url($details['rsa']['n']),
                    'e' => self::base64Url($details['rsa']['e']),
                ],
            ],
        ];
    }

    /**
     * Sign the given claims into a compact RS256 JWT.
     *
     * @param array<string, mixed> $claims
     */
    public function sign(array $claims): string
    {
        return JWT::encode($claims, $this->privatePem, 'RS256', $this->kid);
    }

    private static function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
