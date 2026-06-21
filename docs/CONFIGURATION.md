# Configuration Guide

Setting up Synology SSO Server and configuring this package.

## Synology SSO Server setup

### 1. Install and enable

1. **Package Center** → search **SSO Server** → install.
2. Open **SSO Server** → **Settings** → check **Enable SSO Server**.
3. Set the **Base URL** (e.g. `https://sso.example.com/webman/sso`) → **Apply**.

### 2. Find your host URL

Under **SSO Server → Services → OIDC**, copy the **Well-Known URL** and remove
the trailing `/.well-known/openid-configuration`. The remainder is your
`SYNOLOGY_SSO_HOST`:

- Well-Known URL: `https://sso.example.com/webman/sso/.well-known/openid-configuration`
- `SYNOLOGY_SSO_HOST`: `https://sso.example.com/webman/sso`

### 3. Create the OAuth client

**Application Portal** → **Create** → **OAuth 2.0 Client**:

| Field | Value |
|-------|-------|
| Name | Your application name |
| Application Type | Web Application |
| Redirect URIs | `https://your-app.com/auth/synology/callback` (exact match) |
| Scopes | `openid`, `email`, `groups` |

Save, then copy the **Client ID** and **Client Secret**.

### 4. Groups

Under **Control Panel → User & Group**, Synology has two built-in groups,
`administrators` and `users`. Create more as needed and assign users. Group names
appear bare without Domain/LDAP, or with an `@domain` suffix when LDAP is
configured (see [SYNOLOGY_QUIRKS.md](SYNOLOGY_QUIRKS.md#4-groups-format-depends-on-ldap)).

## Laravel configuration

Install and publish the config:

```bash
composer require deroy2112/laravel-synology-sso
php artisan synology-sso:install
```

Set the environment variables (the rest have defaults in
`config/synology-sso.php`):

```env
SYNOLOGY_SSO_HOST=https://sso.example.com/webman/sso
SYNOLOGY_SSO_CLIENT_ID=your-client-id
SYNOLOGY_SSO_CLIENT_SECRET=your-client-secret
SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"

# Optional (defaults shown)
SYNOLOGY_SSO_AUTO_CREATE_USERS=true
SYNOLOGY_SSO_DEFAULT_ROLE=user
SYNOLOGY_SSO_VERIFY_SSL=true
SYNOLOGY_SSO_CACHE_DURATION=3600
SYNOLOGY_SSO_LEEWAY=60
```

`SYNOLOGY_SSO_REDIRECT_URI` must match the value registered in Synology exactly
(protocol, domain, port, path, trailing slash).

## Group-to-role mapping

Edit `config/synology-sso.php`. Keys are Synology group names (bare and/or
`@domain` form); values are one role or an array of roles:

```php
'group_role_mappings' => [
    'administrators'             => 'admin',
    'users'                      => 'user',
    'developers'                 => ['developer', 'user'],
    // Domain/LDAP variants, if configured:
    'administrators@example.com' => 'admin',
    'users@example.com'          => 'user',
],

// Primary role when a user maps to several:
'role_priority' => ['super-admin', 'admin', 'moderator', 'user'],

// Restrict login to these groups (empty = allow all authenticated users):
'allowed_groups' => ['administrators', 'users'],

// Role for users matching no group; set null to deny them:
'default_role' => 'user',
```

Keys can also be driven from `.env`, e.g.
`env('SYNOLOGY_SSO_ADMIN_GROUP', 'administrators') => 'admin'`.

`GroupRoleMapper` exposes `mapGroupsToRoles()`, `getPrimaryRole()`,
`getAllRoles()`, `hasAccess()`, and `hasRequiredGroup()`. Laravel has no built-in
role system, so apply the returned roles with your own (e.g.
`spatie/laravel-permission`).

## Token lifetime

Synology tokens expire after 180s and there are no refresh tokens. Raise the
limit on the NAS as described in
[SYNOLOGY_QUIRKS.md](SYNOLOGY_QUIRKS.md#1-token-lifetime-180s-default).

## User provisioning

`UserProvisioner` finds or creates the local user from the SSO user, honouring
`auto_create_users` and `user_model`. Point `user_model` at your model if it
isn't `App\Models\User`:

```php
'user_model'        => App\Models\User::class,
'auto_create_users' => true, // false = users must already exist
```

Usage is shown in the [README](../README.md#usage).

## Development with self-signed certificates

```env
SYNOLOGY_SSO_VERIFY_SSL=false
```

Never disable SSL verification in production.

## Troubleshooting

- **`redirect_uri_mismatch`** — the request URI doesn't exactly match the one
  registered in Application Portal (check protocol, port, trailing slash).
- **`Invalid state`** — CSRF state mismatch; ensure cookies/sessions work and
  avoid multiple concurrent login tabs.
- **`Token expired`** — the 180s default; extend the lifetime (see quirks).
- **SSL certificate problem** — self-signed cert in dev; set
  `SYNOLOGY_SSO_VERIFY_SSL=false` for development only.
- **Wrong role** — verify the user's groups in Control Panel → User & Group and
  that the group format (bare vs `@domain`) matches your `group_role_mappings`.
