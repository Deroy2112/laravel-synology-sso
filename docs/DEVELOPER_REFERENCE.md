# Developer Reference

Technical reference for the Synology SSO OIDC endpoints — for implementing custom
flows, debugging, or extending this package. For full sample responses see
[API_RESPONSES.md](API_RESPONSES.md); for server quirks see
[SYNOLOGY_QUIRKS.md](SYNOLOGY_QUIRKS.md).

## 1. Endpoints

Discovery: `GET https://{host}/.well-known/openid-configuration` returns the
endpoint URLs and capabilities (full document in API_RESPONSES.md). The endpoints
are:

| Endpoint | URL |
|----------|-----|
| Authorization | `https://{host}/webman/sso/SSOOauth.cgi` |
| Token | `https://{host}/webman/sso/SSOAccessToken.cgi` |
| UserInfo | `https://{host}/webman/sso/SSOUserInfo.cgi` |
| JWKS | `jwks_uri` from discovery |

This package reads every endpoint from discovery rather than hardcoding them.

### Authorization request

`GET /webman/sso/SSOOauth.cgi` with:

- `response_type` — `code` (authorization code flow)
- `client_id`
- `redirect_uri` — exact match required (see SYNOLOGY_QUIRKS.md)
- `scope` — space-separated, e.g. `openid email groups`
- `state` — CSRF token (recommended)
- `code_challenge` + `code_challenge_method=S256` — PKCE (recommended)
- `nonce` — optional, bound into the ID token for replay protection
- `prompt` / `display` — optional, limited support

Example:

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

### Token request

`POST /webman/sso/SSOAccessToken.cgi` (`application/x-www-form-urlencoded`):

```
grant_type=authorization_code
&code={CODE}
&redirect_uri={REDIRECT_URI}
&client_id={CLIENT_ID}
&client_secret={CLIENT_SECRET}
&code_verifier={CODE_VERIFIER}   # if PKCE used
```

Returns `access_token`, `token_type` (`Bearer`), `expires_in` (default 180), and
`id_token`. No `refresh_token`.

### UserInfo request

`GET /webman/sso/SSOUserInfo.cgi` with `Authorization: Bearer {ACCESS_TOKEN}`.
Returns `sub` plus `email`/`email_verified`/`groups` depending on scope.

## 2. Scopes & claims

| Scope | ID token claims | UserInfo | Required |
|-------|-----------------|----------|----------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce` | `sub` | Yes |
| `email` | `email`, `email_verified` | `email`, `email_verified` | No |
| `groups` | `groups` | `groups` | No |

`groups` is bare (`["administrators", "users"]`) without LDAP, or suffixed
(`["administrators@example.com", ...]`) with Domain/LDAP.

Unsupported: `offline_access` (no refresh token), `profile`, `address`, `phone`.

## 3. PKCE

Synology supports `S256` and `plain` (RFC 7636), verifier length 43–128. Always
use S256. The verifier is a high-entropy random string; the challenge is its
base64url-encoded SHA-256 hash:

```php
$verifier  = bin2hex(random_bytes(32));                                   // 64 chars
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
```

Send `code_challenge`/`code_challenge_method=S256` on the authorization request,
keep the verifier server-side, and send it as `code_verifier` on the token
exchange. The server checks `SHA256(verifier) == challenge`; a mismatch yields
`invalid_grant`. This package implements this in
`src/SynologySocialiteDriver.php` (`generatePkce()`), storing the verifier in the
session key `synology_sso_code_verifier`.

## 4. ID token verification

ID tokens are RS256-signed JWTs (`header.payload.signature`). To verify:

1. Fetch the JWKS from `jwks_uri`.
2. Match the token header's `kid` to a key in the set.
3. Verify the RS256 signature against that key.
4. Validate claims: `iss` matches the issuer, `aud` matches your `client_id`,
   `exp` is in the future and `iat` not in the future (allow some clock-skew
   leeway), `sub` is present, and `nonce` matches the value sent (if any).

This package does all of the above in `src/SynologySocialiteDriver.php`
(`verifyIdToken()` / `verifyIdTokenClaims()`), caching the JWKS and using
`firebase/php-jwt`. A failure throws `InvalidIdTokenException`.

## 5. Grant types

| Grant type | Supported | Notes |
|------------|-----------|-------|
| `authorization_code` | Yes | Use this (with PKCE) |
| `implicit` | Yes | Deprecated in OAuth 2.1, not recommended |
| `refresh_token` | No | Not issued by Synology |
| `client_credentials` | No | User authentication required |
| `password` | No | Insecure |

Authorization code flow: the client is redirected to SSO, logs in, and is
redirected back with a `code`; the server exchanges the code (plus PKCE verifier)
at the token endpoint for an access token and ID token, then calls UserInfo.

Implicit flow exposes tokens in URL fragments and has no PKCE — use authorization
code instead.

## 6. Error codes

Authorization endpoint (returned as query params on the redirect URI):

| Error | Meaning |
|-------|---------|
| `invalid_request` | Missing/invalid parameter |
| `unauthorized_client` | Client not authorized |
| `access_denied` | User denied consent |
| `unsupported_response_type` | Bad `response_type` (use `code`) |
| `invalid_scope` | Unknown scope (use `openid`/`email`/`groups`) |
| `server_error` | SSO Server error |
| `temporarily_unavailable` | Overloaded; retry with backoff |

Token endpoint (JSON, HTTP 400):

| Error | Meaning |
|-------|---------|
| `invalid_request` | Malformed request / missing `code` |
| `invalid_client` | Bad client credentials |
| `invalid_app_id` | Unknown `client_id` |
| `invalid_grant` | Invalid/expired/reused auth code, redirect or PKCE mismatch |
| `unsupported_grant_type` | Use `authorization_code` |
| `invalid_scope` | Scope exceeds the authorized set |

See API_RESPONSES.md for exact response bodies (note the literal `invalid request`
string returned for a refresh grant).

## 7. Custom (non-Socialite) flow

If you integrate without this package, the flow maps directly onto the endpoints:

```php
// Redirect
$verifier  = bin2hex(random_bytes(32));
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
session(['pkce_verifier' => $verifier]);

$authUrl = config('synology-sso.host') . '/webman/sso/SSOOauth.cgi?' . http_build_query([
    'response_type'         => 'code',
    'client_id'             => config('synology-sso.client_id'),
    'redirect_uri'          => config('synology-sso.redirect_uri'),
    'scope'                 => 'openid email groups',
    'state'                 => Str::random(32),
    'code_challenge'        => $challenge,
    'code_challenge_method' => 'S256',
]);
return redirect($authUrl);

// Callback
$tokens = Http::asForm()->post(config('synology-sso.host') . '/webman/sso/SSOAccessToken.cgi', [
    'grant_type'    => 'authorization_code',
    'code'          => $request->input('code'),
    'redirect_uri'  => config('synology-sso.redirect_uri'),
    'client_id'     => config('synology-sso.client_id'),
    'client_secret' => config('synology-sso.client_secret'),
    'code_verifier' => session('pkce_verifier'),
])->json();

$userInfo = Http::withToken($tokens['access_token'])
    ->get(config('synology-sso.host') . '/webman/sso/SSOUserInfo.cgi')
    ->json();
```

Verify `$tokens['id_token']` against the JWKS before trusting it (section 4).

## 8. Manual testing

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq .
curl -s https://sso.example.com/.well-known/jwks | jq .

# Full code exchange
VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d '=' | tr '+/' '-_')
# Open the SSOOauth.cgi URL with code_challenge=$CHALLENGE in a browser, then:
curl -X POST https://sso.example.com/webman/sso/SSOAccessToken.cgi \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=$VERIFIER"
```

If the driver class isn't found after install, run `php artisan config:clear` and
`composer dump-autoload`. For `invalid_grant`, the auth code likely expired (180s)
or was reused. For an invalid ID-token signature, the JWKS cache may be stale
after key rotation — clear the cache.

## References

- OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7636 (PKCE) — https://datatracker.ietf.org/doc/html/rfc7636
- RFC 6749 (OAuth 2.0) — https://datatracker.ietf.org/doc/html/rfc6749
