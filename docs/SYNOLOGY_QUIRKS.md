# Synology SSO Quirks & Limitations

This document describes important quirks, limitations, and workarounds when working with Synology SSO Server.

## 1. Token Lifetime (180 Second Default)

### The Issue
By design, Synology SSO Server sets all OAuth tokens to expire after **180 seconds (3 minutes)**:
- `access_token`: 180s
- `id_token`: 180s
- `authorization_code`: 180s

This short lifetime is hardcoded and cannot be changed via the SSO Server UI or API.

### The Impact
- Users must re-authenticate every 3 minutes
- No refresh tokens are available (see section 2)
- Applications must handle frequent re-authentication

### The Workaround
You can extend token lifetime by manually editing the Synology configuration file:

**File:** `/var/packages/SSOServer/etc/oidc-config.json`

**Default content:**
```json
{
  "BaseURL": "https://sso.example.com",
  "Enabled": true,
  "ExpAccessToken": 180,
  "ExpAuthCode": 180,
  "ExpIdToken": 180
}
```

**Steps to extend (requires root access):**

1. **Check SSO Server is installed:**
   ```bash
   synopkg list | grep SSOServer
   ```
   Should output: `SSOServer-3.0.6-0485: SSO Server provides...`

2. **Create automated script via DSM Task Scheduler:**
   - Open DSM > Control Panel > Task Scheduler
   - Create > Scheduled Task > User-defined script
   - User: root
   - Schedule: Run on the following date > Do not repeat
   - Task Settings > User-defined script:

   ```bash
   #!/bin/bash

   # Extend Synology SSO token lifetime to 30 minutes (1800 seconds)
   sed -i 's/"ExpAccessToken":180/"ExpAccessToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
   sed -i 's/"ExpIdToken":180/"ExpIdToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
   sed -i 's/"ExpAuthCode":180/"ExpAuthCode":1800/g' /var/packages/SSOServer/etc/oidc-config.json

   # Restart SSO Server to apply changes
   synopkg restart SSOServer
   ```

3. **Run the task immediately** (right-click > Run)

**Recommended Values:**
- Development: 1800 seconds (30 minutes)
- Production: 600-900 seconds (10-15 minutes)
- Maximum: 1800 seconds

**Important Notes:**
- Changes persist across reboots
- DSM updates may reset the file (re-run script after updates)
- Longer tokens = convenience vs. security tradeoff

---

## 2. No Refresh Tokens

### The Issue
Synology SSO Server does **not issue refresh tokens**, even when requested with `offline_access` scope.

**Confirmed via testing:**
- `refresh_token` NOT advertised in `grant_types_supported`
- `offline_access` scope NOT advertised in `scopes_supported`
- Token endpoint returns `invalid request` when attempting refresh grant
- Extensive testing confirms: **NO refresh token support**

### The Impact
- Cannot silently renew access tokens
- Users must re-authenticate when tokens expire
- No persistent sessions without cookies
- Long-lived sessions impossible without token lifetime extension

### Workarounds
1. **Extend token lifetime** (see section 1) - **RECOMMENDED**
2. **Use silent authentication** (see section 3) - limited by browser cookie policies
3. **Accept frequent re-authentication** - most secure but poor UX

---

## 3. Silent Authentication (`prompt=none`) Limitations

### The Issue
Silent token renewal using `prompt=none` requires third-party cookies, which are:
- Blocked by default in Safari
- Blocked by default in Firefox with Enhanced Tracking Protection
- Being phased out in Chrome (2024+)

### The Impact
Silent authentication fails in most modern browsers, showing:
- "interaction_required" error
- User must manually re-authenticate

### Recommendation
**Do not rely on `prompt=none` for production applications.**

Instead:
1. Extend token lifetime via configuration (section 1)
2. Implement graceful re-authentication UI
3. Use session-based authentication (store tokens server-side)

---

## 4. Groups Format

### The Issue
Synology SSO returns groups in **two different formats** depending on LDAP configuration:

**Without Domain/LDAP (Standard Synology Groups):**
```json
{
  "groups": [
    "admins",
    "users"
  ]
}
```

**With Domain/LDAP Integration:**
```json
{
  "groups": [
    "admins@example.com",
    "users@example.com"
  ]
}
```

### Important Notes
- Synology has two default groups: **"admins"** and **"users"**
- **Domain/LDAP domains:** Groups include `@domain.com` suffix ONLY when Domain/LDAP is configured
- **Standard mode:** Groups are simple strings without domain
- Group names are case-sensitive
- Empty groups array `[]` means user has no groups

### Best Practices

**Standard Synology (without LDAP):**
```php
'group_role_mappings' => [
    'admins' => 'admin',      // Default Synology admin group
    'users' => 'user',        // Default Synology user group
]
```

**With Domain/LDAP:**
```php
'group_role_mappings' => [
    'admins@example.com' => 'admin',      // LDAP admin group
    'users@example.com' => 'user',        // LDAP user group
]
```

**Supporting Both (Recommended):**
```php
'group_role_mappings' => [
    // Standard Synology groups
    'admins' => 'admin',
    'users' => 'user',

    // Domain/LDAP groups (if Domain/LDAP is enabled)
    'admins@example.com' => 'admin',
    'users@example.com' => 'user',
]
```

---

## 5. OIDC Discovery Endpoint

### The Issue
Synology SSO provides standard OIDC discovery at:
```
https://sso.example.com/.well-known/openid-configuration
```

However:
- Discovery document is not cached by Synology
- Each request fetches fresh data (no ETag/Last-Modified)
- Can cause performance issues with frequent calls

### Recommendation
This package automatically caches the discovery document for 1 hour (configurable):

```php
'cache_duration' => env('SYNOLOGY_SSO_CACHE_DURATION', 3600),
```

---

## 6. JWKS (JSON Web Key Set)

### The Issue
ID tokens are signed with RS256 and require JWKS for verification.

Endpoint: `https://sso.example.com/.well-known/jwks`

### Important Notes
- JWKS contains public keys for signature verification
- Keys may rotate (rare, but possible after updates)
- This package caches JWKS for 1 hour

### What This Package Does
- Automatically fetches and caches JWKS
- Verifies ID token signatures using RS256
- Validates standard claims (iss, aud, exp, iat, sub)

---

## 7. Supported Scopes

### Available Scopes
Synology SSO Server supports only **3 standard OIDC scopes**:

**Confirmed via testing:**
```json
{
  "scopes_supported": [
    "openid",
    "email",
    "groups"
  ]
}
```

### Scope Behavior

**`openid` (Required):**
- Enables OIDC authentication
- Returns basic ID token with `sub`, `iss`, `aud`, `exp`, `iat`

**`email` (Optional):**
- Adds `email` and `email_verified` claims to ID token
- Available via UserInfo endpoint

**`groups` (Optional):**
- Adds `groups` array to ID token
- Format depends on Domain/LDAP configuration (see section 4)
- Available via UserInfo endpoint

**`offline_access` (Not Supported):**
- ❌ NOT in `scopes_supported`
- ❌ Does NOT trigger refresh token issuance
- Requesting this scope has no effect

**Other standard scopes (Not Supported):**
- ❌ `profile` - not advertised
- ❌ `address` - not advertised
- ❌ `phone` - not advertised

### Recommended Scope Combination
```php
'scopes' => ['openid', 'email', 'groups']
```

---

## 8. Client Authentication Method

### The Issue
Synology SSO only supports `client_secret_post` for token endpoint authentication.

**Not supported:**
- `client_secret_basic` (HTTP Basic Auth)
- `private_key_jwt`
- `none` (public clients without PKCE alone)

### What This Package Does
Uses `client_secret_post` by default (credentials in request body).

---

## 9. PKCE Support

### Full PKCE S256 Support Confirmed
Synology SSO Server **fully supports** PKCE (Proof Key for Code Exchange) per RFC 7636.

**Confirmed via testing:**
- ✅ `S256` method advertised and working
- ✅ `plain` method advertised (less secure, not recommended)
- ✅ `code_challenge_methods_supported: ["S256", "plain"]`
- ✅ Verifier length 43-128 characters supported
- ✅ PKCE is optional (backward compatible)

### What This Package Does
**Always uses PKCE S256:**
- Generates cryptographically secure 32-byte verifier (hex-encoded = 64 chars)
- Creates SHA-256 code challenge with base64url encoding
- Protects against authorization code interception attacks
- **Mandatory for public clients** (SPAs, mobile apps)
- **Recommended for all clients** (defense in depth)

**RFC 7636 compliant implementation.**

---

## 10. SSL Certificate Validation

### Development Issue
Self-signed certificates are common in development but cause SSL verification errors.

### Solution
For **development only**, disable SSL verification:

```env
SYNOLOGY_SSO_VERIFY_SSL=false
```

**⚠️ Never disable in production!**

---

## 11. Redirect URI Matching

### The Issue
Synology SSO requires **exact match** of redirect URI:
- Protocol (`http` vs `https`)
- Domain/subdomain
- Port (`:8000` vs `:80`)
- Path (`/callback` vs `/callback/`)
- Trailing slash

### Common Mistakes
```
Configured: https://app.example.com/auth/callback
Request:    https://app.example.com/auth/callback/
Result:     ❌ redirect_uri_mismatch
```

### Best Practice
1. Use environment variables:
   ```env
   SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"
   ```

2. Register multiple URIs in Synology for different environments

---

## Summary Table

| Feature | Synology SSO | Workaround |
|---------|--------------|------------|
| Refresh Tokens | ❌ Not supported | Extend access token lifetime |
| Token Lifetime | ⚠️ 180s default | Edit config file + restart |
| Silent Auth | ⚠️ Requires 3rd-party cookies | Not reliable, extend tokens |
| PKCE S256 | ✅ Fully supported | Always enabled in this package |
| Scopes | ⚠️ Only 3 scopes | `openid`, `email`, `groups` |
| Groups | ✅ Supported | Format varies (w/ or w/o domain) |
| OIDC Discovery | ✅ Supported | Cached by this package |
| RS256 ID Tokens | ✅ Supported | Verified via JWKS |

---

## Need Help?

- Package Issues: https://github.com/Deroy2112/laravel-synology-sso/issues
- Synology SSO Docs: Check your DSM Help Center
- OIDC Specs: https://openid.net/specs/openid-connect-core-1_0.html
