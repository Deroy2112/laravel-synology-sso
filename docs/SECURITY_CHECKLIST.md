# Security Checklist

This document outlines security best practices when implementing Synology SSO authentication.

## ✅ Pre-Production Checklist

### 1. PKCE (Proof Key for Code Exchange)

- [x] **PKCE S256 is always enabled** - This package enforces PKCE for all requests
- [x] **32-byte cryptographic verifier** - Generated using `random_bytes(32)`
- [x] **SHA-256 code challenge** - Computed from verifier
- [x] **Verifier stored securely** - Kept in server-side session, not exposed to client

**Why it matters:** Protects against authorization code interception attacks, even for confidential clients.

---

### 2. State Parameter (CSRF Protection)

- [x] **State parameter included** - Laravel Socialite handles this automatically
- [x] **Cryptographically random** - Generated server-side
- [x] **Verified on callback** - Mismatches reject the request

**Why it matters:** Prevents Cross-Site Request Forgery (CSRF) attacks during OAuth flow.

---

### 3. ID Token Verification

- [x] **Signature verification** - Using JWKS and RS256
- [x] **Issuer (`iss`) validation** - Matches configured SSO host
- [x] **Audience (`aud`) validation** - Matches client ID
- [x] **Expiration (`exp`) check** - Rejects expired tokens
- [x] **Issued-at (`iat`) check** - Prevents time-travel attacks
- [x] **Subject (`sub`) present** - User identifier required

**Manual verification:**
```php
// This package does this automatically
$idTokenClaims = $driver->verifyIdToken($idToken);
```

**Why it matters:** Prevents token forgery, replay attacks, and man-in-the-middle attacks.

---

### 4. Redirect URI Validation

- [ ] **Exact match in Synology SSO** - Configure allowed redirect URIs
- [ ] **Use HTTPS in production** - Never use `http://` for redirect URIs
- [ ] **No wildcards** - Register each URI explicitly
- [ ] **Match protocol, domain, port, and path** - Including trailing slash

**Configuration:**
```env
# ✅ Good - Explicit, HTTPS
SYNOLOGY_SSO_REDIRECT_URI=https://app.example.com/auth/synology/callback

# ❌ Bad - HTTP in production
SYNOLOGY_SSO_REDIRECT_URI=http://app.example.com/auth/callback

# ❌ Bad - Wildcards not supported
SYNOLOGY_SSO_REDIRECT_URI=https://*.example.com/callback
```

**Why it matters:** Prevents authorization code theft via redirect URI manipulation.

---

### 5. Client Secret Protection

- [ ] **Never commit secrets to version control** - Use `.env` files
- [ ] **Rotate secrets regularly** - Every 90 days recommended
- [ ] **Use environment variables** - `SYNOLOGY_SSO_CLIENT_SECRET`
- [ ] **Restrict access** - Only authorized personnel
- [ ] **Different secrets per environment** - Dev/Staging/Production

**Best practices:**
```bash
# ✅ Store in .env (never commit)
SYNOLOGY_SSO_CLIENT_SECRET=your-secret-here

# ❌ Never hardcode in config files
'client_secret' => 'hardcoded-secret', // DON'T DO THIS
```

**Why it matters:** Compromised secrets allow attackers to impersonate your application.

---

### 6. SSL/TLS Configuration

- [ ] **Enable SSL verification in production** - `SYNOLOGY_SSO_VERIFY_SSL=true`
- [ ] **Use valid certificates** - No self-signed certs in production
- [ ] **HTTPS for all endpoints** - SSO host, redirect URI, application
- [ ] **TLS 1.2 or higher** - Disable older protocols

**Configuration:**
```env
# Production
SYNOLOGY_SSO_VERIFY_SSL=true

# Development only (self-signed certs)
SYNOLOGY_SSO_VERIFY_SSL=false
```

**Why it matters:** Prevents man-in-the-middle attacks and eavesdropping.

---

### 7. Token Storage

- [ ] **Server-side sessions only** - Never store tokens in localStorage/cookies
- [ ] **Encrypt session data** - Use Laravel's encrypted cookies
- [ ] **Set secure session cookies** - `SESSION_SECURE_COOKIE=true`
- [ ] **HTTPOnly flag** - Prevents XSS access to cookies
- [ ] **SameSite attribute** - `SESSION_SAME_SITE=lax` or `strict`

**Laravel session config (`config/session.php`):**
```php
'secure' => env('SESSION_SECURE_COOKIE', true), // HTTPS only
'http_only' => true,                             // No JavaScript access
'same_site' => 'lax',                            // CSRF protection
```

**Why it matters:** Prevents token theft via XSS or other client-side attacks.

---

### 8. Group-Based Authorization

- [ ] **Validate groups on every request** - Don't rely on cached roles
- [ ] **Use `allowed_groups` config** - Restrict access to specific groups
- [ ] **Deny by default** - Reject users without mapped groups (set `default_role` to `null`)
- [ ] **Implement role checks** - Use Laravel's authorization features

**Configuration:**
```php
// config/synology-sso.php
'allowed_groups' => [
    // Without Domain/LDAP
    'admins',  // Synology default admin group
    'users',   // Synology default user group

    // With Domain/LDAP (if configured)
    'admins@example.com',
    'users@example.com',
],

'default_role' => null, // Deny access without group mapping
```

**Laravel authorization:**
```php
// In controller
$this->authorize('view', $resource);

// In blade
@can('edit', $post)
    <!-- Edit button -->
@endcan
```

**Why it matters:** Prevents privilege escalation and unauthorized access.

---

### 9. Token Expiration Handling

- [ ] **Monitor token expiration** - Handle `exp` claim
- [ ] **Graceful re-authentication** - Don't expose raw errors to users
- [ ] **Session timeout alignment** - Match Laravel session lifetime to token lifetime
- [ ] **Log authentication events** - Track failed authentications

**Example:**
```php
// Check token expiration before sensitive operations
if ($tokenExp < time()) {
    return redirect()->route('login')->with('error', 'Session expired. Please log in again.');
}
```

**Why it matters:** Reduces attack window and ensures timely re-authentication.

---

### 10. Rate Limiting

- [ ] **Enable rate limiting on auth routes** - Use Laravel's built-in throttle middleware
- [ ] **Limit login attempts** - Prevent brute force attacks
- [ ] **Monitor failed attempts** - Alert on suspicious activity

**Routes example:**
```php
Route::middleware(['throttle:10,1'])->group(function () {
    Route::get('/auth/synology', [AuthController::class, 'redirect']);
    Route::get('/auth/synology/callback', [AuthController::class, 'callback']);
});
```

**Why it matters:** Prevents brute force and DoS attacks.

---

### 11. Input Validation

- [ ] **Validate all OAuth parameters** - Code, state, error responses
- [ ] **Sanitize user data** - Email, username, groups from SSO
- [ ] **Prevent mass assignment** - Use `$fillable` or `$guarded` in User model
- [ ] **Validate redirect parameters** - Prevent open redirect vulnerabilities

**Example:**
```php
// User model
protected $fillable = ['name', 'email']; // Explicitly allow fields

// Controller
$validated = $request->validate([
    'code' => 'required|string',
    'state' => 'required|string',
]);
```

**Why it matters:** Prevents injection attacks and data corruption.

---

### 12. Logging and Monitoring

- [ ] **Log authentication events** - Successful logins, failures, token refresh
- [ ] **Monitor for anomalies** - Unusual login patterns, multiple failures
- [ ] **Alert on security events** - Failed token verification, CSRF attacks
- [ ] **Retain logs securely** - Comply with data retention policies

**Example:**
```php
// Log successful authentication
Log::info('Synology SSO login', [
    'user_id' => $user->id,
    'email' => $user->email,
    'ip' => request()->ip(),
]);

// Log failures
Log::warning('SSO authentication failed', [
    'error' => $exception->getMessage(),
    'ip' => request()->ip(),
]);
```

**Why it matters:** Enables incident response and forensics.

---

## 🔒 Production Deployment Checklist

Before deploying to production:

- [ ] All environment variables configured in `.env`
- [ ] `SYNOLOGY_SSO_VERIFY_SSL=true`
- [ ] Client secret rotated and secured
- [ ] HTTPS enforced for all URLs
- [ ] Session cookies secure (`SESSION_SECURE_COOKIE=true`)
- [ ] Redirect URI registered in Synology SSO (exact match)
- [ ] Group-based authorization configured
- [ ] Rate limiting enabled on auth routes
- [ ] Logging and monitoring in place
- [ ] Security testing completed (penetration test recommended)

---

## 🛡️ Common Security Mistakes

### ❌ DON'T:
- Store tokens in localStorage or client-side cookies
- Disable SSL verification in production
- Use HTTP for redirect URIs
- Commit client secrets to Git
- Skip ID token verification
- Trust user input without validation
- Allow all groups by default

### ✅ DO:
- Use server-side sessions for token storage
- Enable SSL verification always
- Use HTTPS everywhere in production
- Store secrets in environment variables
- Verify ID tokens with JWKS
- Validate and sanitize all input
- Explicitly configure allowed groups

---

## 📚 Additional Resources

- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [Laravel Security Best Practices](https://laravel.com/docs/security)

---

## 🚨 Reporting Security Issues

If you discover a security vulnerability in this package:

1. **DO NOT** open a public issue
2. Email: [Your security contact email]
3. Include: Detailed description, steps to reproduce, impact assessment
4. Allow reasonable time for patching before disclosure

---

**Last Updated:** 2025-01-02
