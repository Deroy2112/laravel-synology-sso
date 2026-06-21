# Security Checklist

Security practices for Synology SSO authentication. Items marked *(automatic)* are
handled by this package; the rest are your responsibility.

## OAuth/OIDC flow

- **PKCE S256** *(automatic)* — always enabled, 32-byte random verifier kept
  server-side, SHA-256 challenge.
- **State parameter** *(automatic)* — Laravel Socialite generates and verifies a
  random state, protecting against CSRF.
- **ID token verification** *(automatic)* — RS256 signature via JWKS, plus `iss`,
  `aud`, `exp`, `iat`, `sub`, and `nonce` checks. A failure throws
  `InvalidIdTokenException`.
- **Redirect URI** — register exact, HTTPS-only URIs in Synology (no wildcards);
  match protocol, domain, port, path, and trailing slash.

## Secrets and transport

- Keep `SYNOLOGY_SSO_CLIENT_SECRET` in `.env`, never in version control; use
  different secrets per environment and rotate periodically.
- `SYNOLOGY_SSO_VERIFY_SSL=true` in production; valid certificates; HTTPS and
  TLS 1.2+ everywhere. Disable verification only for local self-signed certs.

## Sessions and authorization

- Store tokens in server-side sessions only — never `localStorage` or
  client-readable cookies. Set secure session cookies:
  ```php
  // config/session.php
  'secure'    => env('SESSION_SECURE_COOKIE', true),
  'http_only' => true,
  'same_site' => 'lax',
  ```
- Restrict access with `allowed_groups`, and set `default_role` to `null` to deny
  users who match no group. Enforce roles with Laravel's authorization
  (`$this->authorize(...)`, `@can`).

## Hardening

- Rate-limit the auth routes (`throttle` middleware) against brute force/DoS.
- Validate OAuth parameters (`code`, `state`) and use `$fillable` on the User
  model to prevent mass assignment.
- Log auth events (success, failure, failed token verification) with user id and
  IP for incident response.
- Handle token expiry gracefully — re-authenticate instead of surfacing raw
  errors. Note the 180s default lifetime (see SYNOLOGY_QUIRKS.md).

## Before production

- [ ] `SYNOLOGY_SSO_VERIFY_SSL=true`, HTTPS enforced everywhere
- [ ] Client secret secured in `.env`, rotated
- [ ] Redirect URI registered in Synology (exact match)
- [ ] Secure session cookies (`SESSION_SECURE_COOKIE=true`)
- [ ] `allowed_groups` / `default_role` configured
- [ ] Rate limiting on auth routes
- [ ] Auth logging and monitoring in place

## References

- OWASP OAuth 2.0 Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- OAuth 2.0 Security BCP — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- RFC 7636 (PKCE) — https://datatracker.ietf.org/doc/html/rfc7636
- OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Deroy2112/laravel-synology-sso/security/advisories/new),
not public issues.
