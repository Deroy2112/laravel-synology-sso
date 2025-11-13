# Laravel Synology SSO

[![Latest Version on Packagist](https://img.shields.io/packagist/v/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)
[![Total Downloads](https://img.shields.io/packagist/dt/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)
[![License](https://img.shields.io/packagist/l/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)

A Laravel Socialite driver for **Synology SSO Server** with full OIDC support, PKCE S256, ID token verification, and group-to-role mapping.

## Features

- ✅ **PKCE S256** - Secure authorization with Proof Key for Code Exchange (RFC 7636)
- ✅ **ID Token Verification** - RS256 signature validation using JWKS
- ✅ **OIDC Auto-Discovery** - Automatic endpoint configuration
- ✅ **Group-to-Role Mapping** - Map Synology groups to Laravel roles
- ✅ **JIT User Provisioning** - Auto-create users on first login
- ✅ **Laravel 11 & 12 Support** - Compatible with latest Laravel versions
- ✅ **Security Best Practices** - State parameter, SSL verification, secure token storage

## Requirements

- PHP 8.2, 8.3, or 8.4
- Laravel 11.x or 12.x
- Synology DSM with SSO Server package installed
- Valid SSL certificate (or self-signed for development)

## Installation

### Step 1: Install Package

```bash
composer require deroy2112/laravel-synology-sso
```

### Step 2: Run Install Command

```bash
php artisan synology-sso:install
```

This will:
- Publish configuration file to `config/synology-sso.php`
- Optionally publish documentation to `docs/synology-sso/`
- Display environment variable template

### Step 3: Configure Environment

#### Finding Your Synology SSO Host URL

To get the correct `SYNOLOGY_SSO_HOST` value:

1. Open **DSM** > **SSO Server** > **Services** > **OIDC**
2. Locate the **Well-Known URL** field
3. Copy the URL shown (e.g., `https://sso.example.com/webman/sso/.well-known/openid-configuration`)
4. **Remove** `/.well-known/openid-configuration` from the end
5. Use the remaining URL as your `SYNOLOGY_SSO_HOST`

**Example:**
- Well-Known URL: `https://sso.example.com/webman/sso/.well-known/openid-configuration`
- SYNOLOGY_SSO_HOST: `https://sso.example.com/webman/sso`

#### Environment Variables

Add to your `.env` file:

```env
SYNOLOGY_SSO_HOST=https://sso.example.com/webman/sso
SYNOLOGY_SSO_CLIENT_ID=your-client-id
SYNOLOGY_SSO_CLIENT_SECRET=your-client-secret
SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"
```

## Quick Start

### 1. Configure Synology SSO Server

1. Open **DSM** > **SSO Server**
2. Go to **Application Portal** > **Create**
3. Configure OAuth 2.0 Client:
   - **Name:** Your Laravel App
   - **Redirect URIs:** `https://your-app.com/auth/synology/callback`
   - **Scopes:** `openid`, `email`, `groups`
4. Copy **Client ID** and **Client Secret**

### 2. Add Routes

Add to `routes/web.php`:

```php
use Laravel\Socialite\Facades\Socialite;

Route::get('/auth/synology', function () {
    return Socialite::driver('synology')->redirect();
});

Route::get('/auth/synology/callback', function () {
    $user = Socialite::driver('synology')->user();

    // $user->id          - Synology user ID (sub claim)
    // $user->name        - User's display name
    // $user->email       - User's email
    // $user->groups      - Array of groups:
    //                      Without Domain/LDAP: ["administrators", "users"]
    //                      With Domain/LDAP:    ["administrators@example.com", "users@example.com"]

    // Find or create user
    $localUser = User::updateOrCreate(
        ['email' => $user->email],
        ['name' => $user->name]
    );

    Auth::login($localUser);

    return redirect('/dashboard');
});
```

### 3. Add Login Button

```blade
<a href="{{ url('/auth/synology') }}" class="btn btn-primary">
    Login with Synology SSO
</a>
```

## Group-to-Role Mapping

### Configuration

Edit `config/synology-sso.php`:

```php
'group_role_mappings' => [
    // Without Domain/LDAP (Standard Synology)
    'administrators' => 'admin',
    'users' => 'user',

    // With Domain/LDAP (if configured)
    'administrators@example.com' => 'admin',
    'users@example.com' => 'user',

    // Multiple roles example
    'developers' => ['developer', 'user'],
],

'default_role' => 'user', // Or null to deny unmapped users
```

**Note:** Group format depends on LDAP configuration:
- **Without Domain/LDAP**: `administrators`, `users`
- **With Domain/LDAP**: `administrators@domain.com`, `users@domain.com`

### Usage in Controller

```php
use Deroy2112\LaravelSynologySso\GroupRoleMapper;

Route::get('/auth/synology/callback', function (GroupRoleMapper $mapper) {
    $ssoUser = Socialite::driver('synology')->user();

    // Check access
    if (!$mapper->hasAccess($ssoUser->groups)) {
        abort(403, 'Access denied');
    }

    // Get roles
    $roles = $mapper->mapGroupsToRoles($ssoUser->groups);
    // Returns: ['admin', 'user']

    // Get primary role
    $primaryRole = $mapper->getPrimaryRole($ssoUser->groups);
    // Returns: 'admin' (based on role_priority config)

    // Create/update user
    $user = User::updateOrCreate(
        ['email' => $ssoUser->email],
        ['name' => $ssoUser->name]
    );

    // Assign roles (e.g., with spatie/laravel-permission)
    $user->syncRoles($roles);

    Auth::login($user);

    return redirect('/dashboard');
});
```

## Extending Token Lifetime

**Problem:** Synology SSO tokens expire after 180 seconds (3 minutes) by default.

**Solution:** Use DSM Task Scheduler to extend token lifetime.

### Automated Script (Recommended)

1. Open **DSM** > **Control Panel** > **Task Scheduler**
2. Create > **Scheduled Task** > **User-defined script**
3. Configure:
   - **User:** root
   - **Schedule:** Run on the following date (one-time)
4. **Script:**

```bash
#!/bin/bash

# Check if SSO Server is installed
if ! synopkg list | grep -q "SSOServer"; then
    echo "Error: SSO Server not installed"
    exit 1
fi

# Backup original config
cp /var/packages/SSOServer/etc/oidc-config.json \
   /var/packages/SSOServer/etc/oidc-config.json.bak

# Extend token lifetime to 30 minutes (1800 seconds)
sed -i 's/"ExpAccessToken":180/"ExpAccessToken":1800/g' \
    /var/packages/SSOServer/etc/oidc-config.json
sed -i 's/"ExpIdToken":180/"ExpIdToken":1800/g' \
    /var/packages/SSOServer/etc/oidc-config.json
sed -i 's/"ExpAuthCode":180/"ExpAuthCode":1800/g' \
    /var/packages/SSOServer/etc/oidc-config.json

# Restart SSO Server to apply changes
synopkg restart SSOServer

echo "Token lifetime extended to 1800 seconds (30 minutes)"
```

5. Click **OK** and **Run** the task

### Verification

Check the config file:

```bash
cat /var/packages/SSOServer/etc/oidc-config.json
```

Expected output:

```json
{
  "BaseURL": "https://sso.example.com",
  "Enabled": true,
  "ExpAccessToken": 1800,
  "ExpAuthCode": 1800,
  "ExpIdToken": 1800
}
```

**Note:** Changes persist across reboots but may be reset by DSM updates. Re-run the script after updates.

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SYNOLOGY_SSO_HOST` | Yes | - | Synology SSO Server URL |
| `SYNOLOGY_SSO_CLIENT_ID` | Yes | - | OAuth Client ID |
| `SYNOLOGY_SSO_CLIENT_SECRET` | Yes | - | OAuth Client Secret |
| `SYNOLOGY_SSO_REDIRECT_URI` | Yes | `${APP_URL}/auth/synology/callback` | OAuth redirect URI |
| `SYNOLOGY_SSO_AUTO_CREATE_USERS` | No | `true` | JIT user provisioning |
| `SYNOLOGY_SSO_DEFAULT_ROLE` | No | `user` | Default role (or `null`) |
| `SYNOLOGY_SSO_VERIFY_SSL` | No | `true` | SSL verification |
| `SYNOLOGY_SSO_CACHE_DURATION` | No | `3600` | OIDC/JWKS cache (seconds) |

### Group Configuration

```php
// config/synology-sso.php

'allowed_groups' => [
    // Without Domain/LDAP
    'administrators',
    'users',

    // With Domain/LDAP (optional)
    'administrators@example.com',
    'users@example.com',
], // Empty = allow all

'role_priority' => [
    'admin',      // Highest priority
    'moderator',
    'user',       // Lowest priority
],
```

## Advanced Usage

### Custom User Creation

```php
Route::get('/auth/synology/callback', function () {
    $ssoUser = Socialite::driver('synology')->user();

    $user = User::firstOrNew(['email' => $ssoUser->email]);

    if (!$user->exists) {
        // Custom logic for new users
        $user->fill([
            'name' => $ssoUser->name,
            'synology_id' => $ssoUser->id,
            'email_verified_at' => now(), // Trust SSO email
        ])->save();
    }

    Auth::login($user);

    return redirect('/dashboard');
});
```

### With Rate Limiting

```php
Route::middleware(['throttle:10,1'])->group(function () {
    Route::get('/auth/synology', [SsoController::class, 'redirect']);
    Route::get('/auth/synology/callback', [SsoController::class, 'callback']);
});
```

### Logout

```php
Route::post('/logout', function () {
    Auth::logout();
    request()->session()->invalidate();
    request()->session()->regenerateToken();

    return redirect('/');
});
```

## Documentation

- **[Configuration Guide](docs/CONFIGURATION.md)** - Complete setup instructions
- **[Synology Quirks](docs/SYNOLOGY_QUIRKS.md)** - Known issues and workarounds
- **[Developer Reference](docs/DEVELOPER_REFERENCE.md)** - Technical deep-dive (OIDC endpoints, PKCE, ID token verification)
- **[API Response Examples](docs/API_RESPONSES.md)** - Real-world response examples from Synology SSO
- **[Security Checklist](docs/SECURITY_CHECKLIST.md)** - Best practices

## Testing

```bash
composer install
vendor/bin/phpunit
```

## Security

### Best Practices

- ✅ Always use HTTPS in production
- ✅ Enable SSL verification (`SYNOLOGY_SSO_VERIFY_SSL=true`)
- ✅ Rotate client secrets regularly
- ✅ Use group-based authorization
- ✅ Enable rate limiting on auth routes
- ✅ Store tokens server-side only (sessions)

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Email: [Your security contact - replace this]

## Synology SSO Limitations

| Feature | Status | Workaround |
|---------|--------|------------|
| Refresh Tokens | ❌ Not supported | Extend access token lifetime |
| Token Lifetime | ⚠️ 180s default | Edit config file (see above) |
| Silent Auth | ⚠️ Unreliable | Use extended tokens |
| PKCE | ✅ Supported | Always enabled |
| Groups | ✅ Supported | Format: `name@domain.com` |

See [SYNOLOGY_QUIRKS.md](docs/SYNOLOGY_QUIRKS.md) for details.

## Troubleshooting

### "redirect_uri_mismatch"

**Solution:** Ensure exact match in Synology SSO Server configuration (including protocol, domain, port, and trailing slash).

### "Invalid state"

**Solution:** Enable cookies, check session configuration.

### "Token expired"

**Solution:** [Extend token lifetime](#extending-token-lifetime) to 1800 seconds.

### "SSL certificate problem"

**Solution (dev only):**
```env
SYNOLOGY_SSO_VERIFY_SSL=false
```

### Debug Mode

```env
APP_DEBUG=true
```

Check logs:
```bash
tail -f storage/logs/laravel.log
```

## Changelog

Please see [CHANGELOG.md](CHANGELOG.md) for recent changes.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Credits

- [Deroy2112](https://github.com/Deroy2112)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Links

- **Packagist:** https://packagist.org/packages/deroy2112/laravel-synology-sso
- **GitHub:** https://github.com/Deroy2112/laravel-synology-sso
- **Issues:** https://github.com/Deroy2112/laravel-synology-sso/issues
- **Laravel Socialite:** https://laravel.com/docs/socialite
- **Synology SSO Server:** Available in DSM Package Center
