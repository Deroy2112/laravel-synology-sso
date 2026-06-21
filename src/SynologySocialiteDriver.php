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
use Deroy2112\LaravelSynologySso\Exceptions\MissingPkceVerifierException;

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
     * Shared HTTP client configured with the package's TLS settings.
     */
    protected ?Client $synologyClient = null;

    /**
     * Fallback cache TTL (seconds) for OIDC discovery and JWKS.
     */
    private const DEFAULT_CACHE_TTL = 3600;

    /**
     * Default tolerance (seconds) for clock skew between the NAS and this app
     * when checking time-based ID token claims.
     */
    private const DEFAULT_CLOCK_SKEW_LEEWAY = 60;

    /**
     * Number of random bytes used to build the OIDC nonce.
     */
    private const NONCE_BYTES = 16;

    /**
     * Guzzle options applied to every request the driver makes.
     *
     * @return array<string, mixed>
     */
    protected function httpClientOptions(): array
    {
        return [
            'verify' => config('synology-sso.verify_ssl', true),
        ];
    }

    /**
     * Get the shared, TLS-configured HTTP client used for all Synology requests.
     */
    protected function synologyHttpClient(): Client
    {
        if ($this->synologyClient === null) {
            $this->synologyClient = new Client($this->httpClientOptions());
        }

        return $this->synologyClient;
    }

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

        $ttl = (int) config('synology-sso.cache_duration', self::DEFAULT_CACHE_TTL);

        $this->oidcConfig = Cache::remember($cacheKey, $ttl, function () use ($baseUrl) {
            $response = $this->synologyHttpClient()->get($baseUrl . '/.well-known/openid-configuration');

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

        // Generate and store nonce for ID token replay protection
        $nonce = bin2hex(random_bytes(self::NONCE_BYTES));
        session(['synology_sso_nonce' => $nonce]);

        return $this->buildAuthUrlFromBase($config['authorization_endpoint'], $state) .
            '&code_challenge=' . $pkce['challenge'] .
            '&code_challenge_method=S256' .
            '&nonce=' . $nonce;
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
            throw new MissingPkceVerifierException(
                'PKCE code verifier missing from session; the authorization request may have expired or the session was lost.'
            );
        }

        $response = $this->synologyHttpClient()->post($this->getTokenUrl(), [
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
        $response = $this->synologyHttpClient()->get($this->getUserByTokenUrl(), [
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
        $ttl = (int) config('synology-sso.cache_duration', self::DEFAULT_CACHE_TTL);

        $jwks = Cache::remember($cacheKey, $ttl, function () use ($jwksUri) {
            $response = $this->synologyHttpClient()->get($jwksUri);
            return json_decode($response->getBody()->getContents(), true);
        });

        $leeway = (int) config('synology-sso.leeway', self::DEFAULT_CLOCK_SKEW_LEEWAY);

        try {
            // Parse and verify JWT signature with JWKS, tolerating minor clock skew
            JWT::$leeway = $leeway;
            $decoded = JWT::decode($idToken, JWK::parseKeySet($jwks));
            $claims = (array) $decoded;

            // Verify claims
            $this->verifyIdTokenClaims($claims, $config, $leeway);
            $this->verifyNonce($claims);

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
     * @param int $leeway Tolerance in seconds for clock skew on time-based claims.
     * @return void
     * @throws InvalidIdTokenException
     */
    protected function verifyIdTokenClaims(array $claims, array $config, int $leeway = 0): void
    {
        // Verify issuer
        if (!isset($claims['iss']) || $claims['iss'] !== $config['issuer']) {
            throw new InvalidIdTokenException('Invalid issuer');
        }

        // Verify audience. The aud claim may be a single string or an array of
        // strings (RFC 7519); this client must be among them.
        $audiences = isset($claims['aud']) ? (array) $claims['aud'] : [];
        if (!in_array($this->clientId, $audiences, true)) {
            throw new InvalidIdTokenException('Invalid audience');
        }

        // Verify authorized party: when present it must reference this client.
        if (isset($claims['azp']) && $claims['azp'] !== $this->clientId) {
            throw new InvalidIdTokenException('Invalid authorized party');
        }

        // Verify expiration
        if (!isset($claims['exp']) || $claims['exp'] < (time() - $leeway)) {
            throw new InvalidIdTokenException('Token expired');
        }

        // Verify issued at
        if (!isset($claims['iat']) || $claims['iat'] > (time() + $leeway)) {
            throw new InvalidIdTokenException('Token used before issued');
        }

        // Verify subject
        if (!isset($claims['sub'])) {
            throw new InvalidIdTokenException('Missing subject claim');
        }
    }

    /**
     * Verify the ID token nonce against the value stored during the auth request.
     *
     * Only enforced when a nonce was issued for this flow (i.e. the interactive
     * redirect flow); the stored nonce is single-use and cleared after checking.
     *
     * @param array $claims
     * @return void
     * @throws InvalidIdTokenException
     */
    protected function verifyNonce(array $claims): void
    {
        $expectedNonce = session('synology_sso_nonce');

        if ($expectedNonce === null) {
            return;
        }

        session()->forget('synology_sso_nonce');

        if (!isset($claims['nonce']) || !hash_equals($expectedNonce, (string) $claims['nonce'])) {
            throw new InvalidIdTokenException('Invalid nonce');
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
