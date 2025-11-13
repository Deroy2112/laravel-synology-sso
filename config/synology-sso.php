<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Synology SSO Host
    |--------------------------------------------------------------------------
    |
    | The base URL of your Synology SSO Server (without trailing slash).
    | Example: https://sso.example.com/webman/sso
    |
    */

    'host' => env('SYNOLOGY_SSO_HOST'),

    /*
    |--------------------------------------------------------------------------
    | Client Credentials
    |--------------------------------------------------------------------------
    |
    | OAuth 2.0 client credentials obtained from Synology SSO Server.
    | Register your application in SSO Server > Application Portal.
    |
    */

    'client_id' => env('SYNOLOGY_SSO_CLIENT_ID'),

    'client_secret' => env('SYNOLOGY_SSO_CLIENT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Redirect URI
    |--------------------------------------------------------------------------
    |
    | The redirect URI for OAuth callback. Must match the URI registered
    | in Synology SSO Server exactly (including protocol and trailing slash).
    |
    */

    'redirect_uri' => env('SYNOLOGY_SSO_REDIRECT_URI', env('APP_URL') . '/auth/synology/callback'),

    /*
    |--------------------------------------------------------------------------
    | Group to Role Mappings
    |--------------------------------------------------------------------------
    |
    | Map Synology SSO groups to Laravel roles/permissions.
    |
    | Synology default groups: "administrators" and "users"
    |
    | Group format depends on LDAP configuration:
    | - Without Domain/LDAP: "administrators", "users"
    | - With Domain/LDAP:    "administrators@domain.com", "users@domain.com"
    |
    | Example (without LDAP):
    | 'administrators' => 'admin',
    | 'users' => 'user',
    |
    | Example (with LDAP):
    | 'administrators@example.com' => 'admin',
    | 'users@example.com' => 'user',
    |
    | Support both (recommended):
    | 'administrators' => 'admin',
    | 'administrators@example.com' => 'admin',
    |
    */

    'group_role_mappings' => [
        // Standard Synology groups (without LDAP)
        // env('SYNOLOGY_SSO_ADMIN_GROUP', 'administrators') => 'admin',
        // env('SYNOLOGY_SSO_USER_GROUP', 'users') => 'user',

        // Domain/LDAP groups (with @domain.com)
        // env('SYNOLOGY_SSO_ADMIN_GROUP', 'administrators@example.com') => 'admin',
        // env('SYNOLOGY_SSO_USER_GROUP', 'users@example.com') => 'user',
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Role
    |--------------------------------------------------------------------------
    |
    | Default role assigned to users who don't match any group mappings.
    | Set to null to deny access to users without mapped groups.
    |
    */

    'default_role' => env('SYNOLOGY_SSO_DEFAULT_ROLE', 'user'),

    /*
    |--------------------------------------------------------------------------
    | Role Priority
    |--------------------------------------------------------------------------
    |
    | When a user has multiple roles, define the priority order.
    | The first matching role will be used as the primary role.
    |
    */

    'role_priority' => [
        'admin',
        'moderator',
        'user',
    ],

    /*
    |--------------------------------------------------------------------------
    | Allowed Groups
    |--------------------------------------------------------------------------
    |
    | Restrict access to specific groups. If empty, all authenticated users
    | from Synology SSO are allowed. Set specific groups to restrict access.
    |
    | Without Domain/LDAP: ['administrators', 'users']
    | With Domain/LDAP:    ['administrators@example.com', 'users@example.com']
    |
    */

    'allowed_groups' => array_filter([
        // env('SYNOLOGY_SSO_ALLOWED_GROUP_1'),
        // env('SYNOLOGY_SSO_ALLOWED_GROUP_2'),
    ]),

    /*
    |--------------------------------------------------------------------------
    | Auto-Create Users
    |--------------------------------------------------------------------------
    |
    | Automatically create user accounts (JIT provisioning) on first login.
    | If false, users must exist in the database before authentication.
    |
    */

    'auto_create_users' => env('SYNOLOGY_SSO_AUTO_CREATE_USERS', true),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The User model class to use for JIT provisioning.
    |
    */

    'user_model' => env('SYNOLOGY_SSO_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | Token Lifetime
    |--------------------------------------------------------------------------
    |
    | IMPORTANT: Synology SSO default token lifetime is 180 seconds (3 minutes).
    | This cannot be changed via API. To extend token lifetime:
    |
    | 1. SSH into your Synology NAS as root
    | 2. Edit: /var/packages/SSOServer/etc/oidc-config.json
    | 3. Change ExpAccessToken, ExpIdToken, ExpAuthCode (max 1800 seconds)
    | 4. Restart: synopkg restart SSOServer
    |
    | See README.md for automated script using Task Scheduler.
    |
    */

    'token_lifetime_note' => 'See documentation for extending token lifetime beyond 180s',

    /*
    |--------------------------------------------------------------------------
    | SSL Verification
    |--------------------------------------------------------------------------
    |
    | Enable/disable SSL certificate verification for HTTPS requests.
    | Only disable for development with self-signed certificates.
    |
    */

    'verify_ssl' => env('SYNOLOGY_SSO_VERIFY_SSL', true),

    /*
    |--------------------------------------------------------------------------
    | Cache Settings
    |--------------------------------------------------------------------------
    |
    | Cache duration (in seconds) for OIDC discovery and JWKS.
    |
    */

    'cache_duration' => env('SYNOLOGY_SSO_CACHE_DURATION', 3600),

];
