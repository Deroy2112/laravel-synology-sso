# Developer Reference

Technical deep-dive into Synology SSO Server integration.

**Target Audience:** Developers implementing custom SSO flows, debugging issues, or extending this package.

---

## Table of Contents

1. [OIDC Endpoints](#1-oidc-endpoints)
2. [Supported Scopes & Claims](#2-supported-scopes--claims)
3. [PKCE Implementation](#3-pkce-implementation)
4. [ID Token Verification](#4-id-token-verification)
5. [Grant Types](#5-grant-types)
6. [Error Codes](#6-error-codes)
7. [Integration Patterns](#7-integration-patterns)
8. [Testing & Debugging](#8-testing--debugging)

---

## 1. OIDC Endpoints

### Discovery Endpoint
```
GET https://{host}/.well-known/openid-configuration
```

**Key Fields:**
```json
{
  "issuer": "https://sso.example.com",
  "authorization_endpoint": "https://sso.example.com/webman/sso/SSOOauth.cgi",
  "token_endpoint": "https://sso.example.com/webman/sso/SSOAccessToken.cgi",
  "userinfo_endpoint": "https://sso.example.com/webman/sso/SSOUserInfo.cgi",
  "jwks_uri": "https://sso.example.com/.well-known/jwks",
  "scopes_supported": ["openid", "email", "groups"],
  "response_types_supported": ["code", "code id_token", "id_token", "id_token token"],
  "grant_types_supported": ["authorization_code", "implicit"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"]
}
```

### Authorization Endpoint
```
GET https://{host}/webman/sso/SSOOauth.cgi
```

**Required Parameters:**
- `response_type` - Must be `code` (authorization code flow)
- `client_id` - OAuth client identifier
- `redirect_uri` - Exact match required (see SYNOLOGY_QUIRKS.md)
- `scope` - Space-separated scopes (e.g., `openid email groups`)
- `state` - CSRF protection token (recommended)

**PKCE Parameters (Recommended):**
- `code_challenge` - Base64url-encoded SHA256 hash of verifier
- `code_challenge_method` - Must be `S256`

**Optional Parameters:**
- `nonce` - Replay attack prevention (binds to ID token)
- `prompt` - `none`, `login`, `consent` (limited browser support)
- `display` - `page`, `popup`, `touch`, `wap` (provider-specific)

**Example:**
```
https://sso.example.com/webman/sso/SSOOauth.cgi
  ?response_type=code
  &client_id=abc123
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &scope=openid%20email%20groups
  &state=xyz789
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

### Token Endpoint
```
POST https://{host}/webman/sso/SSOAccessToken.cgi
Content-Type: application/x-www-form-urlencoded
```

**Authorization Code Grant:**
```
grant_type=authorization_code
&code={AUTHORIZATION_CODE}
&redirect_uri={REDIRECT_URI}
&client_id={CLIENT_ID}
&client_secret={CLIENT_SECRET}
&code_verifier={CODE_VERIFIER}  # If PKCE used
```

**Response (Success):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
  "token_type": "Bearer",
  "expires_in": 180,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI..."
}
```

**Note:** No `refresh_token` in response (not supported).

### UserInfo Endpoint
```
GET https://{host}/webman/sso/SSOUserInfo.cgi
Authorization: Bearer {ACCESS_TOKEN}
```

**Response:**
```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["administrators", "users"]
}
```

### JWKS Endpoint
```
GET https://{host}/.well-known/jwks
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id-123",
      "alg": "RS256",
      "n": "modulus...",
      "e": "AQAB"
    }
  ]
}
```

---

## 2. Supported Scopes & Claims

### Scope Matrix

| Scope | ID Token Claims | UserInfo Fields | Required |
|-------|----------------|-----------------|----------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce` | `sub` | ✅ Yes |
| `email` | `email`, `email_verified` | `email`, `email_verified` | ❌ No |
| `groups` | `groups` (array) | `groups` (array) | ❌ No |

### Standard Claims

**Always Present (openid scope):**
```json
{
  "sub": "username",              // Subject (username)
  "iss": "https://sso.example.com", // Issuer
  "aud": "client-id",             // Audience (your client_id)
  "exp": 1730000000,              // Expiration timestamp
  "iat": 1729999820,              // Issued at timestamp
  "nonce": "abc123"               // Nonce from auth request (if provided)
}
```

**Email Claims (email scope):**
```json
{
  "email": "user@example.com",
  "email_verified": true
}
```

**Group Claims (groups scope):**
```json
{
  "groups": ["administrators", "users"]
}
```

**Without Domain/LDAP:**
```json
{
  "groups": ["administrators", "users"]
}
```

**With Domain/LDAP:**
```json
{
  "groups": ["administrators@example.com", "users@example.com"]
}
```

### Unsupported Scopes

The following standard OIDC scopes are **NOT supported**:
- `offline_access` - Does not grant refresh tokens
- `profile` - Not advertised
- `address` - Not advertised
- `phone` - Not advertised

---

## 3. PKCE Implementation

### Overview
PKCE (Proof Key for Code Exchange) protects against authorization code interception attacks.

**RFC 7636 Compliance:**
- ✅ S256 method (SHA-256)
- ✅ plain method (not recommended)
- ✅ Verifier length: 43-128 characters

### Step-by-Step Implementation

#### Step 1: Generate Code Verifier

**Requirements:**
- Length: 43-128 characters
- Characters: `[A-Z]`, `[a-z]`, `[0-9]`, `-`, `.`, `_`, `~`
- Cryptographically random

**PHP Example:**
```php
function generateCodeVerifier(): string
{
    // Generate 32 random bytes, hex-encode = 64 characters
    return bin2hex(random_bytes(32));
}

// OR: Base64url-encode 32 bytes = 43 characters
function generateCodeVerifierBase64(): string
{
    $bytes = random_bytes(32);
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
```

**JavaScript Example:**
```javascript
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

function base64URLEncode(buffer) {
    return btoa(String.fromCharCode.apply(null, buffer))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
```

#### Step 2: Generate Code Challenge

**S256 Method (Recommended):**
```php
function generateCodeChallenge(string $verifier): string
{
    $hash = hash('sha256', $verifier, true);
    return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
}
```

**JavaScript Example:**
```javascript
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hash);
    return base64URLEncode(hashArray);
}
```

**Plain Method (Not Recommended):**
```php
function generateCodeChallengePlain(string $verifier): string
{
    return $verifier; // Challenge = Verifier
}
```

#### Step 3: Authorization Request

**URL Parameters:**
```
https://sso.example.com/webman/sso/SSOOauth.cgi
  ?response_type=code
  &client_id={CLIENT_ID}
  &redirect_uri={REDIRECT_URI}
  &scope=openid email groups
  &state={STATE}
  &code_challenge={CODE_CHALLENGE}
  &code_challenge_method=S256
```

**Store `code_verifier` securely** (session, secure cookie, etc.) for step 4.

#### Step 4: Token Exchange

**POST Parameters:**
```
grant_type=authorization_code
&code={AUTHORIZATION_CODE}
&redirect_uri={REDIRECT_URI}
&client_id={CLIENT_ID}
&client_secret={CLIENT_SECRET}
&code_verifier={CODE_VERIFIER}
```

**Server Verification:**
```
SHA256(code_verifier) == code_challenge
```

If match fails: `invalid_grant` error.

### PKCE in This Package

The `SynologySocialiteDriver` automatically handles PKCE:

```php
protected function generatePkce(): array
{
    // 32 bytes = 64 hex characters
    $verifier = bin2hex(random_bytes(32));

    // SHA-256 hash + base64url encoding
    $challenge = rtrim(
        strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
        '='
    );

    return [
        'verifier' => $verifier,
        'challenge' => $challenge,
    ];
}
```

**Storage:**
```php
session(['synology_sso_pkce_verifier' => $pkce['verifier']]);
```

**Token Exchange:**
```php
$verifier = session('synology_sso_pkce_verifier');
$response = $this->getAccessTokenResponse($code, $verifier);
```

---

## 4. ID Token Verification

### JWT Structure

ID tokens are RS256-signed JWTs with three parts:
```
header.payload.signature
```

**Example:**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlzcyI6Imh0dHBzOi8vc3NvLmV4YW1wbGUuY29tIiwiYXVkIjoiY2xpZW50LWlkIiwiZXhwIjoxNzMwMDAwMDAwLCJpYXQiOjE3Mjk5OTk4MjB9.signature...
```

### Verification Steps

**1. Fetch JWKS:**
```php
$jwksUrl = 'https://sso.example.com/.well-known/jwks';
$jwks = json_decode(file_get_contents($jwksUrl), true);
```

**2. Extract Key ID from Token Header:**
```php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

$header = JWT::urlsafeB64Decode(explode('.', $idToken)[0]);
$kid = json_decode($header, true)['kid'];
```

**3. Verify Signature:**
```php
$keys = JWK::parseKeySet($jwks);
$decoded = JWT::decode($idToken, $keys);
```

**4. Validate Claims:**
```php
// Issuer must match SSO host
if ($decoded->iss !== config('synology-sso.host')) {
    throw new InvalidIdTokenException('Invalid issuer');
}

// Audience must match client_id
if ($decoded->aud !== config('synology-sso.client_id')) {
    throw new InvalidIdTokenException('Invalid audience');
}

// Token must not be expired
if ($decoded->exp < time()) {
    throw new InvalidIdTokenException('Token expired');
}

// Issued at must be in the past
if ($decoded->iat > time() + 60) { // 60s clock skew tolerance
    throw new InvalidIdTokenException('Token issued in future');
}

// Subject must be present
if (empty($decoded->sub)) {
    throw new InvalidIdTokenException('Missing subject claim');
}
```

### This Package's Implementation

```php
protected function verifyIdToken(string $idToken): array
{
    $jwksUrl = $this->getSsoHost() . '/.well-known/jwks';

    // Fetch and cache JWKS
    $jwks = Cache::remember("synology_sso_jwks", 3600, function () use ($jwksUrl) {
        return json_decode(file_get_contents($jwksUrl), true);
    });

    $keys = JWK::parseKeySet($jwks);
    $decoded = JWT::decode($idToken, $keys);

    // Validate claims
    $this->validateClaims($decoded);

    return (array) $decoded;
}
```

---

## 5. Grant Types

### Supported Grant Types

| Grant Type | Supported | Use Case |
|------------|-----------|----------|
| `authorization_code` | ✅ Yes | Web apps, server-side apps |
| `implicit` | ✅ Yes | **Not recommended** (deprecated in OAuth 2.1) |
| `refresh_token` | ❌ No | N/A - Synology doesn't support |
| `client_credentials` | ❌ No | N/A - User authentication required |
| `password` | ❌ No | N/A - Insecure, not recommended |

### Authorization Code Flow (Recommended)

**Sequence Diagram:**
```
Client                  Synology SSO              Application Server
  |                           |                           |
  |---(1) Redirect to SSO---->|                           |
  |                           |                           |
  |<--(2) Login Page----------|                           |
  |                           |                           |
  |---(3) Submit Creds------->|                           |
  |                           |                           |
  |<--(4) Auth Code-----------|                           |
  |                           |                           |
  |---(5) Send Auth Code------|-------------------------->|
  |                           |                           |
  |                           |<--(6) Exchange Code-------|
  |                           |                           |
  |                           |---(7) Access + ID Token-->|
  |                           |                           |
  |<--(8) User Info + Session-------------------------|
```

### Implicit Flow (Not Recommended)

**Deprecated in OAuth 2.1** due to security concerns:
- Tokens exposed in URL fragments
- No PKCE protection
- Cannot authenticate confidential clients

**Use authorization code flow with PKCE instead.**

---

## 6. Error Codes

### Authorization Endpoint Errors

Returned as query parameters in redirect URI:
```
https://app.example.com/callback?error={ERROR_CODE}&error_description={DESCRIPTION}&state={STATE}
```

| Error Code | Description | Solution |
|------------|-------------|----------|
| `invalid_request` | Missing or invalid parameter | Check all required params |
| `unauthorized_client` | Client not authorized | Verify client_id in SSO config |
| `access_denied` | User denied consent | User action, retry login |
| `unsupported_response_type` | Invalid response_type | Use `code` |
| `invalid_scope` | Unknown scope requested | Use only `openid`, `email`, `groups` |
| `server_error` | SSO Server error | Check SSO Server logs |
| `temporarily_unavailable` | SSO Server overloaded | Retry with backoff |

### Token Endpoint Errors

Returned as JSON in response body (HTTP 400):
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

| Error Code | Description | Solution |
|------------|-------------|----------|
| `invalid_request` | Malformed request | Check POST parameters |
| `invalid_client` | Invalid client credentials | Verify client_id/client_secret |
| `invalid_grant` | Invalid/expired auth code | Code used twice or expired (180s) |
| `unauthorized_client` | Client not authorized for grant | Use `authorization_code` grant |
| `unsupported_grant_type` | Grant type not supported | Use `authorization_code` |
| `invalid_scope` | Scope exceeds authorized | Match auth request scopes |

### Common Integration Errors

**Error: "redirect_uri_mismatch"**
```
Configured: https://app.example.com/callback
Request:    https://app.example.com/callback/
```
**Solution:** Ensure exact match (trailing slash, protocol, port).

**Error: "invalid_grant" on token exchange**
```
Possible causes:
- Authorization code already used
- Authorization code expired (180s default)
- redirect_uri mismatch
- PKCE verifier mismatch
```

**Error: "Invalid signature" on ID token**
```
Possible causes:
- JWKS cache stale (key rotation)
- Clock skew between servers
- Corrupted ID token
```
**Solution:** Clear JWKS cache, check server time sync.

---

## 7. Integration Patterns

### Pattern 1: Standard Laravel Socialite Integration

```php
use Laravel\Socialite\Facades\Socialite;

// routes/web.php
Route::get('/auth/synology', function () {
    return Socialite::driver('synology')->redirect();
});

Route::get('/auth/synology/callback', function () {
    $user = Socialite::driver('synology')->user();

    // $user->getId()        // Synology username
    // $user->getEmail()     // Email address
    // $user->getName()      // Username (same as ID)
    // $user->groups         // Groups array

    // Find or create user
    $localUser = User::updateOrCreate(
        ['email' => $user->getEmail()],
        [
            'name' => $user->getName(),
            'synology_id' => $user->getId(),
        ]
    );

    // Map groups to roles
    $mapper = app(GroupRoleMapper::class);
    $role = $mapper->getPrimaryRole($user->groups ?? []);
    $localUser->assignRole($role);

    // Login
    Auth::login($localUser);

    return redirect('/dashboard');
});
```

### Pattern 2: Manual OAuth Flow (Without Socialite)

```php
use Illuminate\Support\Facades\Http;

class SynologyOAuthController extends Controller
{
    public function redirectToProvider()
    {
        // Generate PKCE
        $verifier = bin2hex(random_bytes(32));
        $challenge = $this->generateCodeChallenge($verifier);

        session(['pkce_verifier' => $verifier]);

        // Build authorization URL
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => config('synology-sso.client_id'),
            'redirect_uri' => config('synology-sso.redirect_uri'),
            'scope' => 'openid email groups',
            'state' => Str::random(32),
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        $authUrl = config('synology-sso.host') . '/webman/sso/SSOOauth.cgi?' . $query;

        return redirect($authUrl);
    }

    public function handleProviderCallback(Request $request)
    {
        $code = $request->input('code');
        $verifier = session('pkce_verifier');

        // Exchange code for tokens
        $response = Http::asForm()->post(
            config('synology-sso.host') . '/webman/sso/SSOAccessToken.cgi',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => config('synology-sso.redirect_uri'),
                'client_id' => config('synology-sso.client_id'),
                'client_secret' => config('synology-sso.client_secret'),
                'code_verifier' => $verifier,
            ]
        );

        $tokens = $response->json();

        // Verify ID token
        $claims = $this->verifyIdToken($tokens['id_token']);

        // Get user info
        $userInfo = Http::withToken($tokens['access_token'])
            ->get(config('synology-sso.host') . '/webman/sso/SSOUserInfo.cgi')
            ->json();

        // Handle user creation/login
        // ...
    }

    private function generateCodeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }
}
```

### Pattern 3: Middleware-Based Access Control

```php
use Deroy2112\LaravelSynologySso\GroupRoleMapper;

class CheckSynologyGroup
{
    protected GroupRoleMapper $mapper;

    public function __construct(GroupRoleMapper $mapper)
    {
        $this->mapper = $mapper;
    }

    public function handle(Request $request, Closure $next, ...$requiredGroups)
    {
        $user = $request->user();
        $userGroups = $user->synology_groups ?? [];

        if (!$this->mapper->hasRequiredGroup($userGroups, $requiredGroups)) {
            abort(403, 'Insufficient permissions');
        }

        return $next($request);
    }
}

// Usage in routes
Route::middleware(['auth', 'synology.group:administrators'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index']);
});
```

---

## 8. Testing & Debugging

### Testing OIDC Discovery

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq .
```

**Expected Output:**
```json
{
  "issuer": "https://sso.example.com",
  "authorization_endpoint": "https://sso.example.com/webman/sso/SSOOauth.cgi",
  "token_endpoint": "https://sso.example.com/webman/sso/SSOAccessToken.cgi",
  ...
}
```

### Testing JWKS Endpoint

```bash
curl -s https://sso.example.com/.well-known/jwks | jq .
```

**Expected Output:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      ...
    }
  ]
}
```

### Testing Authorization Flow (Manual)

```bash
# Step 1: Generate PKCE
VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d '=' | tr '+/' '-_')

# Step 2: Build authorization URL
AUTH_URL="https://sso.example.com/webman/sso/SSOOauth.cgi?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https://app.example.com/callback&scope=openid%20email%20groups&state=test123&code_challenge=$CHALLENGE&code_challenge_method=S256"

echo "Open in browser: $AUTH_URL"

# Step 3: After login, extract code from redirect
# https://app.example.com/callback?code=AUTH_CODE&state=test123

# Step 4: Exchange code for tokens
curl -X POST https://sso.example.com/webman/sso/SSOAccessToken.cgi \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=$VERIFIER"
```

### Debugging Token Issues

**Enable logging in this package:**

```php
// config/synology-sso.php
'debug' => env('SYNOLOGY_SSO_DEBUG', false),
```

**Check logs:**
```bash
tail -f storage/logs/laravel.log
```

**Decode ID Token (without verification):**
```bash
echo "eyJhbGc..." | cut -d. -f2 | base64 -d | jq .
```

### Common Debugging Scenarios

**Issue: "Class SynologySocialiteDriver not found"**
```bash
php artisan config:clear
php artisan cache:clear
composer dump-autoload
```

**Issue: "redirect_uri_mismatch"**
```bash
# Check configured URI
php artisan tinker
>>> config('synology-sso.redirect_uri')

# Ensure exact match in Synology SSO Server config
```

**Issue: "Invalid signature" on ID token**
```bash
# Clear JWKS cache
php artisan cache:forget synology_sso_jwks

# Check clock sync
date
```

**Issue: Token expired immediately**
```bash
# Check token lifetime in response
curl ... | jq '.expires_in'

# Default is 180s, extend via config file (see SYNOLOGY_QUIRKS.md)
```

---

## Additional Resources

- **Package Repository:** https://github.com/Deroy2112/laravel-synology-sso
- **OIDC Spec:** https://openid.net/specs/openid-connect-core-1_0.html
- **RFC 7636 (PKCE):** https://datatracker.ietf.org/doc/html/rfc7636
- **RFC 6749 (OAuth 2.0):** https://datatracker.ietf.org/doc/html/rfc6749
- **Synology SSO Quirks:** See `docs/SYNOLOGY_QUIRKS.md`
- **Security Checklist:** See `docs/SECURITY_CHECKLIST.md`

---

**Document Version:** 1.0.0
**Last Updated:** 2025-11-02
