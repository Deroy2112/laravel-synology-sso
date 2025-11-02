<?php

namespace Deroy2112\LaravelSynologySso;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use GuzzleHttp\Client;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Deroy2112\LaravelSynologySso\Exceptions\InvalidIdTokenException;

class SynologySocialiteDriver extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['openid', 'email', 'groups'];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * PKCE code verifier (stored in session).
     *
     * @var string|null
     */
    protected $codeVerifier;

    /**
     * OIDC discovery configuration.
     *
     * @var array|null
     */
    protected $oidcConfig;

    /**
     * Get the OIDC discovery configuration.
     *
     * @return array
     */
    protected function getOidcConfig(): array
    {
        if ($this->oidcConfig !== null) {
            return $this->oidcConfig;
        }

        $baseUrl = rtrim(config('synology-sso.host'), '/');
        $cacheKey = 'synology_sso_oidc_config_' . md5($baseUrl);

        $this->oidcConfig = Cache::remember($cacheKey, 3600, function () use ($baseUrl) {
            $client = new Client();
            $response = $client->get($baseUrl . '/.well-known/openid-configuration');

            return json_decode($response->getBody()->getContents(), true);
        });

        return $this->oidcConfig;
    }

    /**
     * Generate PKCE code verifier and challenge.
     *
     * @return array{verifier: string, challenge: string}
     */
    protected function generatePkce(): array
    {
        // Generate 32-byte random verifier (RFC 7636)
        $verifier = bin2hex(random_bytes(32));

        // Create SHA-256 challenge
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return [
            'verifier' => $verifier,
            'challenge' => $challenge,
        ];
    }

    /**
     * Get the authentication URL for the provider.
     *
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state): string
    {
        $config = $this->getOidcConfig();

        // Generate and store PKCE verifier
        $pkce = $this->generatePkce();
        session(['synology_sso_code_verifier' => $pkce['verifier']]);

        return $this->buildAuthUrlFromBase($config['authorization_endpoint'], $state) .
            '&code_challenge=' . $pkce['challenge'] .
            '&code_challenge_method=S256';
    }

    /**
     * Get the token URL for the provider.
     *
     * @return string
     */
    protected function getTokenUrl(): string
    {
        $config = $this->getOidcConfig();
        return $config['token_endpoint'];
    }

    /**
     * Get the user info URL for the provider.
     *
     * @return string
     */
    protected function getUserByTokenUrl(): string
    {
        $config = $this->getOidcConfig();
        return $config['userinfo_endpoint'];
    }

    /**
     * Get the access token response for the given code.
     *
     * @param string $code
     * @return array
     */
    public function getAccessTokenResponse($code): array
    {
        // Retrieve PKCE verifier from session
        $codeVerifier = session('synology_sso_code_verifier');

        if (!$codeVerifier) {
            throw new \RuntimeException('PKCE code verifier not found in session');
        }

        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'form_params' => $this->getTokenFields($code),
        ]);

        // Clear the verifier from session
        session()->forget('synology_sso_code_verifier');

        return json_decode($response->getBody(), true);
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param string $code
     * @return array
     */
    protected function getTokenFields($code): array
    {
        $codeVerifier = session('synology_sso_code_verifier');

        return [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * Get the raw user for the given access token.
     *
     * @param string $token
     * @return array
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get($this->getUserByTokenUrl(), [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * Verify and decode the ID token.
     *
     * @param string $idToken
     * @return array
     * @throws InvalidIdTokenException
     */
    protected function verifyIdToken(string $idToken): array
    {
        $config = $this->getOidcConfig();
        $jwksUri = $config['jwks_uri'];

        // Fetch JWKS (with caching)
        $cacheKey = 'synology_sso_jwks_' . md5($jwksUri);
        $jwks = Cache::remember($cacheKey, 3600, function () use ($jwksUri) {
            $client = new Client();
            $response = $client->get($jwksUri);
            return json_decode($response->getBody()->getContents(), true);
        });

        try {
            // Parse and verify JWT signature with JWKS
            $decoded = JWT::decode($idToken, JWK::parseKeySet($jwks));
            $claims = (array) $decoded;

            // Verify claims
            $this->verifyIdTokenClaims($claims, $config);

            return $claims;
        } catch (\Exception $e) {
            throw new InvalidIdTokenException('ID token verification failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Verify ID token claims.
     *
     * @param array $claims
     * @param array $config
     * @return void
     * @throws InvalidIdTokenException
     */
    protected function verifyIdTokenClaims(array $claims, array $config): void
    {
        // Verify issuer
        if (!isset($claims['iss']) || $claims['iss'] !== $config['issuer']) {
            throw new InvalidIdTokenException('Invalid issuer');
        }

        // Verify audience
        if (!isset($claims['aud']) || $claims['aud'] !== $this->clientId) {
            throw new InvalidIdTokenException('Invalid audience');
        }

        // Verify expiration
        if (!isset($claims['exp']) || $claims['exp'] < time()) {
            throw new InvalidIdTokenException('Token expired');
        }

        // Verify issued at
        if (!isset($claims['iat']) || $claims['iat'] > time()) {
            throw new InvalidIdTokenException('Token used before issued');
        }

        // Verify subject
        if (!isset($claims['sub'])) {
            throw new InvalidIdTokenException('Missing subject claim');
        }
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param array $user
     * @return \Laravel\Socialite\Two\User
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['username'] ?? $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? $user['username'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['picture'] ?? null,
            'groups' => $user['groups'] ?? [],
        ]);
    }

    /**
     * Get a Social User instance from a known access token and ID token.
     *
     * @param string $token
     * @param string|null $idToken
     * @return \Laravel\Socialite\Two\User
     */
    public function userFromTokenAndId(string $token, ?string $idToken = null): User
    {
        $user = $this->getUserByToken($token);

        // Verify ID token if provided
        if ($idToken) {
            $idTokenClaims = $this->verifyIdToken($idToken);

            // Merge ID token claims with user info
            $user = array_merge($user, $idTokenClaims);
        }

        return $this->mapUserToObject($user);
    }

    /**
     * Override user method to include ID token verification.
     *
     * @return \Laravel\Socialite\Two\User
     */
    public function user(): User
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new \InvalidArgumentException('Invalid state');
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $this->user = $this->userFromTokenAndId(
            $response['access_token'],
            $response['id_token'] ?? null
        );

        return $this->user->setToken($response['access_token'])
            ->setRefreshToken($response['refresh_token'] ?? null)
            ->setExpiresIn($response['expires_in'] ?? null);
    }
}
