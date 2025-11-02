# Synology SSO API Response Examples

Real-world response examples from Synology SSO Server endpoints. All sensitive data (domains, client IDs, keys) has been sanitized.

**Purpose:** Help developers understand exact response structures for debugging and integration.

---

## Table of Contents

1. [OIDC Discovery](#1-oidc-discovery)
2. [JWKS Endpoint](#2-jwks-endpoint)
3. [Token Endpoint](#3-token-endpoint)
4. [UserInfo Endpoint](#4-userinfo-endpoint)
5. [Authorization Errors](#5-authorization-errors)
6. [Token Errors](#6-token-errors)
7. [UserInfo Errors](#7-userinfo-errors)

---

## 1. OIDC Discovery

### Request
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: sso.example.com
```

### Response (200 OK)
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

### Key Observations

**Supported Features:**
- ✅ PKCE (S256 and plain methods)
- ✅ Authorization Code Flow
- ✅ Implicit Flow (deprecated, not recommended)
- ✅ Three scopes: `openid`, `email`, `groups`
- ✅ RS256 signature for ID tokens

**Missing Features:**
- ❌ No `refresh_token` in `grant_types_supported`
- ❌ No `offline_access` in `scopes_supported`
- ❌ No `profile`, `address`, `phone` scopes

**Quirk:**
- `issuer` field has `/webman/sso` suffix, but **NOT** on the actual endpoints
- Endpoints do NOT include `/webman/sso` prefix (just `/webman/sso/SSOOauth.cgi`)

---

## 2. JWKS Endpoint

### Request
```http
GET /.well-known/jwks HTTP/1.1
Host: sso.example.com
```

### Response (200 OK)
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

### Structure

| Field | Description | Example Value |
|-------|-------------|---------------|
| `alg` | Algorithm | `RS256` |
| `e` | RSA public exponent | `AQAB` (65537 in base64) |
| `kid` | Key ID (for matching) | `synology-sso-key-1` |
| `kty` | Key type | `RSA` |
| `n` | RSA modulus (base64url) | Long base64 string |
| `use` | Public key use | `sig` (signature) |

### Usage

```php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

// Fetch JWKS
$jwks = json_decode(file_get_contents('https://sso.example.com/.well-known/jwks'), true);

// Parse keys
$keys = JWK::parseKeySet($jwks);

// Verify ID token
$idToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...';
$decoded = JWT::decode($idToken, $keys);
```

---

## 3. Token Endpoint

### Successful Token Exchange

#### Request
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

#### Response (200 OK)
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlzcyI6Imh0dHBzOi8vc3NvLmV4YW1wbGUuY29tL3dlYm1hbi9zc28iLCJhdWQiOiJ5b3VyLWNsaWVudC1pZCIsImV4cCI6MTczMDAwMDE4MCwiaWF0IjoxNzMwMDAwMDAwfQ.signature...",
  "token_type": "Bearer",
  "expires_in": 180,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN5bm9sb2d5LXNzby1rZXktMSJ9.eyJzdWIiOiJ1c2VybmFtZSIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW5zIiwidXNlcnMiXSwiaXNzIjoiaHR0cHM6Ly9zc28uZXhhbXBsZS5jb20vd2VibWFuL3NzbyIsImF1ZCI6InlvdXItY2xpZW50LWlkIiwiZXhwIjoxNzMwMDAwMTgwLCJpYXQiOjE3MzAwMDAwMDAsIm5vbmNlIjoiYWJjMTIzIn0.signature..."
}
```

### ID Token Decoded (Header)
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "synology-sso-key-1"
}
```

### ID Token Decoded (Payload)
```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["admins", "users"],
  "iss": "https://sso.example.com/webman/sso",
  "aud": "your-client-id",
  "exp": 1730000180,
  "iat": 1730000000,
  "nonce": "abc123"
}
```

### Token Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `access_token` | JWT | Bearer token for UserInfo endpoint |
| `token_type` | String | Always `Bearer` |
| `expires_in` | Integer | Lifetime in seconds (default: 180) |
| `id_token` | JWT | OIDC ID token with user claims |
| `refresh_token` | - | ❌ NOT PRESENT (not supported) |

### ID Token Claims

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | ✅ Yes | Subject (username) |
| `iss` | ✅ Yes | Issuer (SSO server URL) |
| `aud` | ✅ Yes | Audience (your client_id) |
| `exp` | ✅ Yes | Expiration timestamp |
| `iat` | ✅ Yes | Issued at timestamp |
| `nonce` | ⚠️ If sent | Echo of authorization nonce |
| `email` | ❌ No | User email (if `email` scope) |
| `email_verified` | ❌ No | Email verification status |
| `groups` | ❌ No | Groups array (if `groups` scope) |

---

## 4. UserInfo Endpoint

### Successful UserInfo Request

#### Request
```http
GET /webman/sso/SSOUserInfo.cgi HTTP/1.1
Host: sso.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response (200 OK)

**With `openid email groups` scopes:**
```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["admins", "users"]
}
```

**With only `openid` scope:**
```json
{
  "sub": "username"
}
```

**With Domain/LDAP enabled:**
```json
{
  "sub": "username",
  "email": "user@example.com",
  "email_verified": true,
  "groups": ["admins@example.com", "users@example.com"]
}
```

### UserInfo Fields by Scope

| Scope | Fields Included |
|-------|-----------------|
| `openid` | `sub` |
| `openid email` | `sub`, `email`, `email_verified` |
| `openid groups` | `sub`, `groups` |
| `openid email groups` | `sub`, `email`, `email_verified`, `groups` |

---

## 5. Authorization Errors

### Error: Missing client_id

#### Request
```
GET /webman/sso/SSOOauth.cgi
  ?response_type=code
  &redirect_uri=https://app.example.com/callback
  &scope=openid
```

#### Response (302 Redirect)
```
https://app.example.com/callback
  ?error=invalid_request
  &error_description=Missing+required+parameter:+client_id
  &state=xyz
```

### Error: Invalid redirect_uri

#### Request
```
GET /webman/sso/SSOOauth.cgi
  ?response_type=code
  &client_id=your-client-id
  &redirect_uri=https://wrong-domain.com/callback
  &scope=openid
```

#### Response (400 Bad Request)
```html
<html>
<head><title>Error</title></head>
<body>
<h1>Invalid redirect URI</h1>
</body>
</html>
```

**Note:** When redirect_uri is invalid, error is NOT redirected (cannot trust URI).

### Error: Unsupported response_type

#### Request
```
GET /webman/sso/SSOOauth.cgi
  ?response_type=token
  &client_id=your-client-id
  &redirect_uri=https://app.example.com/callback
```

#### Response (302 Redirect)
```
https://app.example.com/callback
  ?error=unsupported_response_type
  &error_description=Response+type+not+supported
  &state=xyz
```

### Error: Invalid scope

#### Request
```
GET /webman/sso/SSOOauth.cgi
  ?response_type=code
  &client_id=your-client-id
  &redirect_uri=https://app.example.com/callback
  &scope=openid+profile+address
```

#### Response (302 Redirect)
```
https://app.example.com/callback
  ?error=invalid_scope
  &error_description=Unsupported+scope
  &state=xyz
```

---

## 6. Token Errors

### Error: Invalid client_id

#### Request
```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123
&client_id=wrong-client-id
&client_secret=your-secret
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid_app_id"
}
```

### Error: Invalid client_secret

#### Request
```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123
&client_id=your-client-id
&client_secret=wrong-secret
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid_client"
}
```

### Error: Invalid/Expired Authorization Code

#### Request
```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=expired-or-invalid-code
&client_id=your-client-id
&client_secret=your-secret
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid_grant"
}
```

**Common Causes:**
- Authorization code already used
- Authorization code expired (180s default)
- Authorization code never existed
- redirect_uri mismatch
- PKCE verifier mismatch

### Error: Unsupported Grant Type

#### Request
```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=abc123
&client_id=your-client-id
&client_secret=your-secret
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid request"
}
```

**Note:** Synology does NOT support `refresh_token` grant type.

### Error: Missing Required Parameter

#### Request
```http
POST /webman/sso/SSOAccessToken.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=your-client-id
&client_secret=your-secret
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid_request"
}
```

**Cause:** Missing `code` parameter.

---

## 7. UserInfo Errors

### Error: Invalid Access Token

#### Request
```http
GET /webman/sso/SSOUserInfo.cgi HTTP/1.1
Authorization: Bearer invalid-token-here
```

#### Response (400 Bad Request)
```json
{
  "error": "invalid_token"
}
```

### Error: Missing Authorization Header

#### Request
```http
GET /webman/sso/SSOUserInfo.cgi HTTP/1.1
```

#### Response (401 Unauthorized)
```json
{
  "error": "invalid_request"
}
```

### Error: Expired Access Token

#### Request
```http
GET /webman/sso/SSOUserInfo.cgi HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response (401 Unauthorized)
```json
{
  "error": "invalid_token"
}
```

**Note:** Default token lifetime is 180 seconds. Extend via config file (see SYNOLOGY_QUIRKS.md).

### Error: Wrong HTTP Method

#### Request
```http
POST /webman/sso/SSOUserInfo.cgi HTTP/1.1
Authorization: Bearer valid-token
```

#### Response (405 Method Not Allowed)
```json
{
  "error": "invalid_request"
}
```

**Note:** UserInfo endpoint only accepts `GET` requests.

---

## Common Error Response Format

Synology SSO uses two error response formats:

### OAuth 2.0 Standard Format
```json
{
  "error": "error_code",
  "error_description": "Human-readable description"
}
```

### Synology-Specific Format
```json
{
  "error": "error_code"
}
```

**No `error_description` field in most responses.**

---

## HTTP Status Codes

| Status | Meaning | Common Errors |
|--------|---------|---------------|
| 200 | Success | - |
| 302 | Redirect | Authorization errors (via query params) |
| 400 | Bad Request | `invalid_request`, `invalid_grant`, `invalid_client` |
| 401 | Unauthorized | `invalid_token` (expired/missing token) |
| 405 | Method Not Allowed | Wrong HTTP method |
| 500 | Server Error | SSO Server internal error |

---

## Debugging Tips

### Decode JWT Tokens (Without Verification)

**Online:** https://jwt.io

**Command Line:**
```bash
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSJ9.sig" | \
  cut -d. -f2 | \
  base64 -d | \
  jq .
```

### Test OIDC Discovery

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq .
```

### Test JWKS

```bash
curl -s https://sso.example.com/.well-known/jwks | jq .
```

### Test UserInfo (With Valid Token)

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://sso.example.com/webman/sso/SSOUserInfo.cgi | jq .
```

### Common Response Issues

**Issue:** `invalid_token` immediately after token exchange
- **Cause:** Clock skew between servers
- **Solution:** Check server time sync

**Issue:** `invalid_grant` on token exchange
- **Cause:** Authorization code expired (default: 180s)
- **Solution:** Reduce time between authorization and token exchange

**Issue:** Empty `groups` array
- **Cause:** User not assigned to any groups in Synology
- **Solution:** Assign user to groups in DSM > Control Panel > User & Group

**Issue:** Groups have `@domain.com` suffix unexpectedly
- **Cause:** Domain/LDAP integration enabled
- **Solution:** Update group mappings in config to include domain suffix

---

## Additional Resources

- **DEVELOPER_REFERENCE.md** - Integration patterns and code examples
- **SYNOLOGY_QUIRKS.md** - Known limitations and workarounds
- **SECURITY_CHECKLIST.md** - Security best practices

---

**Document Version:** 1.0.0
**Last Updated:** 2025-11-02
**Based On:** Synology DSM 7.x, SSO Server 3.0.6
