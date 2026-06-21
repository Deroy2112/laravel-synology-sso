# Synology SSO Quirks & Limitations

Known quirks, limitations, and workarounds for Synology SSO Server. These are
properties of the server, not bugs in this package.

## 1. Token lifetime (180s default)

All OAuth tokens expire after **180 seconds** by default:

- `access_token`: 180s
- `id_token`: 180s
- `authorization_code`: 180s

This is hardcoded and cannot be changed through the SSO Server UI or API — only
by editing the config file on the NAS (root required):

**File:** `/var/packages/SSOServer/etc/oidc-config.json`

```json
{
  "BaseURL": "https://sso.example.com/webman/sso",
  "Enabled": true,
  "ExpAccessToken": 180,
  "ExpAuthCode": 180,
  "ExpIdToken": 180
}
```

Raise the three `Exp*` values (max 1800) and restart the package. A one-time DSM
Task Scheduler script (run as root) is the convenient way:

```bash
#!/bin/bash
sed -i 's/"ExpAccessToken":180/"ExpAccessToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
sed -i 's/"ExpIdToken":180/"ExpIdToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
sed -i 's/"ExpAuthCode":180/"ExpAuthCode":1800/g' /var/packages/SSOServer/etc/oidc-config.json
synopkg restart SSOServer
```

Suggested values: 1800s (30 min) for dev, 600–900s for production, 1800s max.
Changes persist across reboots but may be reset by DSM updates — re-run after an
update.

## 2. No refresh tokens

Synology SSO does **not** issue refresh tokens, even when `offline_access` is
requested:

- `refresh_token` is not in `grant_types_supported`
- `offline_access` is not in `scopes_supported`
- The token endpoint returns `invalid request` for a refresh grant

There is no silent token renewal. Either extend the token lifetime (section 1)
or accept re-authentication when tokens expire.

## 3. Silent auth (`prompt=none`) is unreliable

Silent renewal via `prompt=none` needs third-party cookies, which are blocked by
default in Safari and Firefox (ETP) and being phased out in Chrome. It typically
fails with `interaction_required`. Do not rely on it in production; extend token
lifetime and implement a graceful re-auth UI instead.

## 4. Groups format depends on LDAP

The `groups` claim has two forms:

- **Without Domain/LDAP:** bare names — `["administrators", "users"]`
- **With Domain/LDAP:** suffixed — `["administrators@example.com", "users@example.com"]`

Notes:

- Synology's two built-in groups are `administrators` and `users`.
- The `@domain.com` suffix appears only when Domain/LDAP is configured.
- Group names are case-sensitive.
- An empty array `[]` means the user has no groups.

Map both forms if you support both setups (replace `@example.com` with your real
domain).

## 5. OIDC discovery

Standard discovery is served at:

```
https://sso.example.com/.well-known/openid-configuration
```

Synology does not cache the discovery document (no ETag/Last-Modified), so
frequent fetches hit the server each time. This package caches it for 1 hour
(`cache_duration`).

## 6. JWKS

ID tokens are signed with RS256; verification uses the JWKS endpoint
(`jwks_uri` from discovery). Keys can rotate (rare, e.g. after updates). This
package fetches and caches JWKS for 1 hour and verifies the RS256 signature plus
the standard claims (`iss`, `aud`, `exp`, `iat`, `sub`).

## 7. Supported scopes

Only three scopes are advertised in `scopes_supported`: `openid`, `email`,
`groups`.

- `openid` (required): basic ID token (`sub`, `iss`, `aud`, `exp`, `iat`).
- `email` (optional): adds `email` and `email_verified`.
- `groups` (optional): adds the `groups` array (format per section 4).

Not supported: `offline_access` (no effect, no refresh token), `profile`,
`address`, `phone` — none are advertised.

## 8. Client authentication

The token endpoint is used with `client_secret_post` (credentials in the request
body). `client_secret_basic`, `private_key_jwt`, and `none` are not used by this
package.

## 9. PKCE

Synology supports PKCE per RFC 7636: `code_challenge_methods_supported` is
`["S256", "plain"]`, verifier length 43–128, and PKCE is optional
(backward-compatible). This package always uses S256 with a 32-byte verifier
(hex-encoded, 64 chars) and a base64url SHA-256 challenge.

## 10. SSL certificate validation

Self-signed certificates are common in development and cause verification errors.
For development only, set `SYNOLOGY_SSO_VERIFY_SSL=false`. Never disable it in
production.

## 11. Redirect URI matching

Synology requires an **exact** match on protocol, domain/subdomain, port, path,
and trailing slash. For example, a registered `…/auth/callback` will reject a
request to `…/auth/callback/` with `redirect_uri_mismatch`. Drive the value from
config (`SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"`) and
register one URI per environment.

## Summary

| Feature | Synology SSO | Notes |
|---------|--------------|-------|
| Refresh tokens | Not supported | Extend access token lifetime |
| Token lifetime | 180s default | Edit `oidc-config.json` + restart |
| Silent auth | Needs 3rd-party cookies | Unreliable; extend tokens |
| PKCE S256 | Supported | Always enabled here |
| Scopes | `openid`, `email`, `groups` only | — |
| Groups | Supported | Bare or `@domain` form |
| OIDC discovery | Supported | Cached by this package |
| RS256 ID tokens | Supported | Verified via JWKS |

## References

- OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html
- Package issues — https://github.com/Deroy2112/laravel-synology-sso/issues
