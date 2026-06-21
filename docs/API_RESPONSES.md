# Synology SSO API Response Examples

Real responses from Synology SSO Server endpoints (DSM 7.x, SSO Server 3.0.6),
with domains, client IDs and keys sanitized. Use them to understand the exact
structures when debugging or integrating.

## 1. OIDC Discovery

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: sso.example.com
```

Response (200 OK):

```json
{
  "authorization_endpoint": "https://sso.example.com/webman/sso/SSOOauth.cgi",
  "claims_supported": [
    "aud",
    "email",
    "exp",
    "groups",
    "iat",
    "iss",
    "sub",
    "username"
  ],
  "code_challenge_methods_supported": [
    "S256",
    "plain"
  ],
  "grant_types_supported": [
    "authorization_code",
    "implicit"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "issuer": "https://sso.example.com/webman/sso",
  "jwks_uri": "https://sso.example.com/webman/sso/openid-jwks.json",
  "response_types_supported": [
    "code",
    "code id_token",
    "id_token",
    "id_token token"
  ],
  "scopes_supported": [
    "email",
    "groups",
    "openid"
  ],
  "subject_types_supported": [
    "public"
  ],
  "token_endpoint": "https://sso.example.com/webman/sso/SSOAccessToken.cgi",
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "userinfo_endpoint": "https://sso.example.com/webman/sso/SSOUserInfo.cgi"
}
```

Notes:

- Supports PKCE (`S256` and `plain`), authorization code and implicit flows, the
  three scopes `openid`/`email`/`groups`, and RS256-signed ID tokens.
- No `refresh_token` in `grant_types_supported`, no `offline_access` in
  `scopes_supported`, and no `profile`/`address`/`phone` scopes.
- `issuer` carries the `/webman/sso` path — that value (with `/webman/sso`) is
  what you set as `SYNOLOGY_SSO_HOST`. Endpoints live under it as `…/webman/sso/SSO*.cgi`.

## 2. JWKS Endpoint

```http
GET /.well-known/jwks HTTP/1.1
Host: sso.example.com
```

Response (200 OK):

```json
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "kid": "synology-sso-key-1",
      "kty": "RSA",
      "n": "xGOr_hCKzi6zNsXvWcvdSdPU7TnXgp_h...truncated...xQEbw",
      "use": "sig"
    }
  ]
}
```

| Field | Description | Example |
|-------|-------------|---------|
| `alg` | Algorithm | `RS256` |
| `e` | RSA public exponent | `AQAB` (65537) |
| `kid` | Key ID (for matching) | `synology-sso-key-1` |
| `kty` | Key type | `RSA` |
| `n` | RSA modulus (base64url) | long base64 string |
| `use` | Public key use | `sig` |

## 3. Token Endpoint

Request:

```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Host: sso.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123def456
&redirect_uri=https://app.example.com/callback
&client_id=your-client-id
&client_secret=your-client-secret
&code_verifier=a1b2c3d4e5f6...
```

Response (200 OK):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 180,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN5bm9sb2d5LXNzby1rZXktMSJ9..."
}
```

ID token header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "synology-sso-key-1"
}
```

ID token payload:

```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["administrators", "users"],
  "iss": "https://sso.example.com/webman/sso",
  "aud": "your-client-id",
  "exp": 1730000180,
  "iat": 1730000000,
  "nonce": "abc123"
}
```

Token response fields:

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | JWT | Bearer token for the UserInfo endpoint |
| `token_type` | String | Always `Bearer` |
| `expires_in` | Integer | Lifetime in seconds (default 180) |
| `id_token` | JWT | OIDC ID token with user claims |
| `refresh_token` | — | Not present (not supported) |

ID token claims:

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Subject (username) |
| `iss` | Yes | Issuer (SSO server URL) |
| `aud` | Yes | Audience (your `client_id`) |
| `exp` | Yes | Expiration timestamp |
| `iat` | Yes | Issued-at timestamp |
| `nonce` | If sent | Echo of the authorization nonce |
| `email` | No | User email (with `email` scope) |
| `email_verified` | No | Email verification status |
| `groups` | No | Groups array (with `groups` scope) |

## 4. UserInfo Endpoint

```http
GET /webman/sso/SSOUserInfo.cgi HTTP/1.1
Host: sso.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response with `openid email groups`:

```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["administrators", "users"]
}
```

With only `openid`:

```json
{
  "sub": "username"
}
```

With Domain/LDAP enabled:

```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["administrators@example.com", "users@example.com"]
}
```

| Scope | Fields |
|-------|--------|
| `openid` | `sub` |
| `openid email` | `sub`, `email`, `email_verified` |
| `openid groups` | `sub`, `groups` |
| `openid email groups` | `sub`, `email`, `email_verified`, `groups` |

## 5. Authorization Errors

**Missing `client_id`** — request omits `client_id`. Response (302):

```
https://app.example.com/callback?error=invalid_request&error_description=Missing+required+parameter:+client_id&state=xyz
```

**Invalid `redirect_uri`** — response is 400 HTML (not redirected, since the URI
cannot be trusted):

```html
<html><head><title>Error</title></head><body><h1>Invalid redirect URI</h1></body></html>
```

**Unsupported `response_type`** (e.g. `token`). Response (302):

```
https://app.example.com/callback?error=unsupported_response_type&error_description=Response+type+not+supported&state=xyz
```

**Invalid scope** (e.g. `openid profile address`). Response (302):

```
https://app.example.com/callback?error=invalid_scope&error_description=Unsupported+scope&state=xyz
```

## 6. Token Errors

All return HTTP 400 with a JSON `error`:

| Condition | Response |
|-----------|----------|
| Invalid `client_id` | `{"error": "invalid_app_id"}` |
| Invalid `client_secret` | `{"error": "invalid_client"}` |
| Invalid/expired/reused auth code | `{"error": "invalid_grant"}` |
| Refresh grant (`grant_type=refresh_token`) | `{"error": "invalid request"}` |
| Missing `code` parameter | `{"error": "invalid_request"}` |

`invalid_grant` causes: code already used, code expired (180s default), code
never existed, `redirect_uri` mismatch, or PKCE verifier mismatch.

Note: the refresh-grant error is the literal string `invalid request` (with a
space), distinct from `invalid_request`.

## 7. UserInfo Errors

| Condition | Status | Response |
|-----------|--------|----------|
| Invalid access token | 400 | `{"error": "invalid_token"}` |
| Missing `Authorization` header | 401 | `{"error": "invalid_request"}` |
| Expired access token | 401 | `{"error": "invalid_token"}` |
| Wrong HTTP method (only `GET` allowed) | 405 | `{"error": "invalid_request"}` |

## Error formats

Synology uses two shapes:

```json
{ "error": "error_code", "error_description": "Human-readable description" }
```

```json
{ "error": "error_code" }
```

Most responses omit `error_description`.

## HTTP status codes

| Status | Meaning | Common errors |
|--------|---------|---------------|
| 200 | Success | — |
| 302 | Redirect | Authorization errors (via query params) |
| 400 | Bad Request | `invalid_request`, `invalid_grant`, `invalid_client` |
| 401 | Unauthorized | `invalid_token` (expired/missing token) |
| 405 | Method Not Allowed | Wrong HTTP method |
| 500 | Server Error | SSO Server internal error |

## Debugging

Inspect the endpoints directly:

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq .
curl -s https://sso.example.com/.well-known/jwks | jq .
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://sso.example.com/webman/sso/SSOUserInfo.cgi | jq .
```

Decode a JWT payload without verifying:

```bash
echo "eyJ...payload..." | cut -d. -f2 | base64 -d | jq .
```

Common issues:

- `invalid_token` right after token exchange → clock skew; check server time sync.
- `invalid_grant` on exchange → auth code expired (180s); shorten the time between
  authorization and exchange.
- Empty `groups` array → user is in no Synology groups (assign under Control Panel
  → User & Group).
- Unexpected `@domain.com` suffix on groups → Domain/LDAP is enabled; include the
  suffix in your group mappings.
