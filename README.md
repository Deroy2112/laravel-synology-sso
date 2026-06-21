# Laravel Synology SSO

[![Latest Version on Packagist](https://img.shields.io/packagist/v/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)
[![Total Downloads](https://img.shields.io/packagist/dt/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)
[![License](https://img.shields.io/packagist/l/deroy2112/laravel-synology-sso.svg?style=flat-square)](https://packagist.org/packages/deroy2112/laravel-synology-sso)

A [Laravel Socialite](https://laravel.com/docs/socialite) driver for Synology SSO Server.
It speaks OIDC with auto-discovery, uses PKCE (S256) and a nonce, verifies the ID
token signature (RS256/JWKS) and claims, and can map Synology groups to your app's roles.

## Requirements

- PHP 8.2+
- Laravel 11 or 12
- A Synology DSM with the SSO Server package, reachable over HTTPS

## Installation

```bash
composer require deroy2112/laravel-synology-sso
php artisan synology-sso:install
```

The install command publishes `config/synology-sso.php`, optionally copies the
docs into your app, and prints an `.env` template.

### Configuration

Set at least these in `.env`:

```env
SYNOLOGY_SSO_HOST=https://sso.example.com/webman/sso
SYNOLOGY_SSO_CLIENT_ID=your-client-id
SYNOLOGY_SSO_CLIENT_SECRET=your-client-secret
SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"
```

`SYNOLOGY_SSO_HOST` is the SSO Server's Well-Known URL with
`/.well-known/openid-configuration` removed — find it under
**DSM → SSO Server → Services → OIDC**. Everything else (group mapping, allowed
groups, SSL verification, cache TTL, clock-skew leeway) lives in the published
config file; see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

On the Synology side, register the app under **SSO Server → Application Portal**
with the redirect URI above and the scopes `openid`, `email`, `groups`.

## Usage

```php
use Deroy2112\LaravelSynologySso\GroupRoleMapper;
use Deroy2112\LaravelSynologySso\UserProvisioner;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

Route::get('/auth/synology', fn () => Socialite::driver('synology')->redirect());

Route::get('/auth/synology/callback', function (UserProvisioner $provisioner, GroupRoleMapper $mapper) {
    $ssoUser = Socialite::driver('synology')->user();

    if (! $mapper->hasAccess($ssoUser->groups)) {
        abort(403);
    }

    // Find or create the local user (honours auto_create_users / user_model).
    $user = $provisioner->provision($ssoUser);

    // Laravel has no built-in roles, so assign them however your app does,
    // e.g. with spatie/laravel-permission:
    // $user->syncRoles($mapper->mapGroupsToRoles($ssoUser->groups));

    Auth::login($user);

    return redirect('/dashboard');
});
```

`$ssoUser` exposes the usual Socialite fields (`id` from the `sub` claim, `name`,
`email`) plus `groups`. Synology group names are bare (`administrators`, `users`)
without LDAP, or suffixed (`administrators@example.com`) with a domain — map both
forms if you support both.

## Token lifetime

Synology issues short-lived tokens (180s by default) and no refresh tokens. That
is a server-side limit, not a driver bug; you can raise it on the NAS. See
[docs/SYNOLOGY_QUIRKS.md](docs/SYNOLOGY_QUIRKS.md).

## Documentation

- [Configuration](docs/CONFIGURATION.md)
- [Synology quirks](docs/SYNOLOGY_QUIRKS.md)
- [Developer reference](docs/DEVELOPER_REFERENCE.md)
- [API response examples](docs/API_RESPONSES.md)
- [Security checklist](docs/SECURITY_CHECKLIST.md)

## Testing

```bash
composer install
vendor/bin/phpunit
```

## Security

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/Deroy2112/laravel-synology-sso/security/advisories/new),
not public issues.

## License

MIT — see [LICENSE](LICENSE).
