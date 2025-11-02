# Configuration Guide

Complete guide to configuring Laravel Synology SSO integration.

## Table of Contents

1. [Synology SSO Server Setup](#synology-sso-server-setup)
2. [Laravel Environment Configuration](#laravel-environment-configuration)
3. [Group-to-Role Mapping](#group-to-role-mapping)
4. [Extending Token Lifetime](#extending-token-lifetime)
5. [Routes Configuration](#routes-configuration)
6. [User Model Setup](#user-model-setup)
7. [Advanced Configuration](#advanced-configuration)
8. [Troubleshooting](#troubleshooting)

---

## Synology SSO Server Setup

### Step 1: Install SSO Server Package

1. Open **Package Center** in DSM
2. Search for **SSO Server**
3. Click **Install**
4. Follow the installation wizard

### Step 2: Enable SSO Server

1. Open **SSO Server** from DSM main menu
2. Go to **Settings** tab
3. Check **Enable SSO Server**
4. Set **Base URL** (e.g., `https://sso.example.com`)
5. Click **Apply**

### Step 3: Create OAuth Application

1. Go to **Application Portal** tab
2. Click **Create** > **OAuth 2.0 Client**
3. Fill in the form:

   | Field | Value |
   |-------|-------|
   | **Name** | Your application name (e.g., "Laravel App") |
   | **Application Type** | Web Application |
   | **Redirect URIs** | `https://your-app.com/auth/synology/callback` |
   | **Scopes** | openid, email, groups |

4. Click **Save**
5. **Copy the Client ID and Client Secret** (you'll need these for Laravel)

### Step 4: Configure User Groups

1. Open **Control Panel** > **User & Group**
2. Go to **Group** tab
3. Synology has two default groups:
   - `admins` - For administrators (built-in)
   - `users` - For regular users (built-in)
4. Create additional groups as needed (e.g., `developers`, `managers`)
5. Assign users to appropriate groups

---

## Laravel Environment Configuration

### Step 1: Install Package

```bash
composer require deroy2112/laravel-synology-sso
php artisan synology-sso:install
```

### Step 2: Configure Environment Variables

Add to your `.env` file:

```env
# Required: Synology SSO Host
SYNOLOGY_SSO_HOST=https://sso.example.com

# Required: OAuth Credentials (from Synology SSO Server)
SYNOLOGY_SSO_CLIENT_ID=your-client-id-here
SYNOLOGY_SSO_CLIENT_SECRET=your-client-secret-here

# Required: Redirect URI (must match Synology SSO configuration exactly)
SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"

# Optional: Auto-create users on first login (default: true)
SYNOLOGY_SSO_AUTO_CREATE_USERS=true

# Optional: Default role for users without group mapping (default: user)
SYNOLOGY_SSO_DEFAULT_ROLE=user

# Optional: SSL verification (disable only for dev with self-signed certs)
SYNOLOGY_SSO_VERIFY_SSL=true

# Optional: Cache duration for OIDC discovery and JWKS (seconds, default: 3600)
SYNOLOGY_SSO_CACHE_DURATION=3600
```

### Step 3: Verify Configuration

Run a quick test:

```bash
php artisan tinker
>>> config('synology-sso.host')
=> "https://sso.example.com"
>>> config('synology-sso.client_id')
=> "your-client-id-here"
```

---

## Group-to-Role Mapping

### Basic Mapping

Edit `config/synology-sso.php`:

**Without Domain/LDAP (Standard Synology):**
```php
'group_role_mappings' => [
    'admins' => 'admin',        // Synology default admin group
    'users' => 'user',          // Synology default user group
    'developers' => 'developer', // Custom group
],
```

**With Domain/LDAP Integration:**
```php
'group_role_mappings' => [
    'admins@example.com' => 'admin',       // LDAP admin group
    'users@example.com' => 'user',         // LDAP user group
    'developers@example.com' => 'developer', // Custom LDAP group
],
```

**Supporting Both (Recommended):**
```php
'group_role_mappings' => [
    // Standard Synology groups (without LDAP)
    'admins' => 'admin',
    'users' => 'user',

    // Domain/LDAP groups (with @domain.com)
    'admins@example.com' => 'admin',
    'users@example.com' => 'user',
],
```

**Important:**
- Synology default groups are `admins` and `users` (not "administrators")
- **@domain.com suffix**: Only present when Domain/LDAP is configured
- Replace `@example.com` with your actual Domain/LDAP domain

### Multiple Roles per Group

```php
'group_role_mappings' => [
    // Without Domain/LDAP
    'admins' => ['admin', 'user'],
    'developers' => ['developer', 'user'],
    'users' => 'user',

    // With Domain/LDAP (optional, if Domain/LDAP is configured)
    'admins@example.com' => ['admin', 'user'],
    'developers@example.com' => ['developer', 'user'],
    'users@example.com' => 'user',
],
```

### Environment-Based Mapping

For dynamic configuration via `.env`:

```php
// config/synology-sso.php
'group_role_mappings' => [
    env('SYNOLOGY_SSO_ADMIN_GROUP', 'admins') => 'admin',
    env('SYNOLOGY_SSO_USER_GROUP', 'users') => 'user',
],
```

Then in `.env`:

**Without Domain/LDAP:**
```env
SYNOLOGY_SSO_ADMIN_GROUP=admins
SYNOLOGY_SSO_USER_GROUP=users
```

**With Domain/LDAP:**
```env
SYNOLOGY_SSO_ADMIN_GROUP=admins@mycompany.com
SYNOLOGY_SSO_USER_GROUP=users@mycompany.com
```

### Role Priority

When users have multiple roles, define priority:

```php
'role_priority' => [
    'super-admin',
    'admin',
    'moderator',
    'user',
],
```

The first matching role becomes the "primary role".

### Restricting Access by Group

Only allow specific groups:

**Without Domain/LDAP:**
```php
'allowed_groups' => [
    'admins',  // Synology default admin group
    'users',   // Synology default user group
],
```

**With Domain/LDAP:**
```php
'allowed_groups' => [
    'admins@example.com',  // LDAP admin group
    'users@example.com',   // LDAP user group
],
```

Users not in these groups will be denied access.

### Deny Users Without Groups

Set `default_role` to `null` to deny access:

```php
'default_role' => null, // No default role - require group mapping
```

---

## Extending Token Lifetime

**Problem:** Synology SSO tokens expire after 180 seconds by default.

**Solution:** Extend token lifetime via DSM Task Scheduler.

### Automated Script (Recommended)

1. Open **DSM** > **Control Panel** > **Task Scheduler**
2. Click **Create** > **Scheduled Task** > **User-defined script**
3. Configure:

   | Setting | Value |
   |---------|-------|
   | **Task name** | Extend SSO Token Lifetime |
   | **User** | root |
   | **Schedule** | Run on the following date (one-time) |

4. In **Task Settings** > **User-defined script**, paste:

   ```bash
   #!/bin/bash

   # Check if SSO Server is installed
   if ! synopkg list | grep -q "SSOServer"; then
       echo "Error: SSO Server not installed"
       exit 1
   fi

   # Backup original config
   cp /var/packages/SSOServer/etc/oidc-config.json /var/packages/SSOServer/etc/oidc-config.json.bak

   # Extend token lifetime to 30 minutes (1800 seconds)
   sed -i 's/"ExpAccessToken":180/"ExpAccessToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
   sed -i 's/"ExpIdToken":180/"ExpIdToken":1800/g' /var/packages/SSOServer/etc/oidc-config.json
   sed -i 's/"ExpAuthCode":180/"ExpAuthCode":1800/g' /var/packages/SSOServer/etc/oidc-config.json

   # Restart SSO Server to apply changes
   synopkg restart SSOServer

   echo "Token lifetime extended to 1800 seconds (30 minutes)"
   ```

5. Click **OK**
6. **Run the task immediately** (right-click > Run)

### Manual Method (SSH)

```bash
# 1. SSH into Synology as root
ssh admin@your-nas-ip
sudo -i

# 2. Backup config
cp /var/packages/SSOServer/etc/oidc-config.json /var/packages/SSOServer/etc/oidc-config.json.bak

# 3. Edit config (replace 180 with 1800)
vi /var/packages/SSOServer/etc/oidc-config.json

# 4. Restart SSO Server
synopkg restart SSOServer
```

### Recommended Values

| Use Case | Seconds | Minutes |
|----------|---------|---------|
| Development | 1800 | 30 min |
| Production (low security) | 1800 | 30 min |
| Production (medium security) | 900 | 15 min |
| Production (high security) | 600 | 10 min |
| Maximum allowed | 1800 | 30 min |

**Note:** Changes persist across reboots but may be reset by DSM updates.

---

## Routes Configuration

### Basic Routes

Add to `routes/web.php`:

```php
use Laravel\Socialite\Facades\Socialite;
use App\Http\Controllers\Auth\SynologySsoController;

// Redirect to Synology SSO
Route::get('/auth/synology', function () {
    return Socialite::driver('synology')->redirect();
})->name('synology.redirect');

// Handle callback
Route::get('/auth/synology/callback', function () {
    $user = Socialite::driver('synology')->user();

    // Handle user authentication (see User Model Setup below)

    return redirect('/dashboard');
})->name('synology.callback');
```

### Controller-Based Approach (Recommended)

Create `app/Http/Controllers/Auth/SynologySsoController.php`:

```php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use Deroy2112\LaravelSynologySso\GroupRoleMapper;

class SynologySsoController extends Controller
{
    public function redirect()
    {
        return Socialite::driver('synology')->redirect();
    }

    public function callback(GroupRoleMapper $mapper)
    {
        try {
            $ssoUser = Socialite::driver('synology')->user();

            // Check if user has access
            if (!$mapper->hasAccess($ssoUser->groups ?? [])) {
                abort(403, 'You do not have permission to access this application.');
            }

            // Find or create user
            $user = User::updateOrCreate(
                ['email' => $ssoUser->email],
                [
                    'name' => $ssoUser->name,
                    'synology_id' => $ssoUser->id,
                ]
            );

            // Assign roles
            $roles = $mapper->mapGroupsToRoles($ssoUser->groups ?? []);
            $user->syncRoles($roles); // If using spatie/laravel-permission

            // Log in
            Auth::login($user, true);

            return redirect()->intended('/dashboard');

        } catch (\Exception $e) {
            report($e);
            return redirect('/login')->with('error', 'Authentication failed. Please try again.');
        }
    }

    public function logout()
    {
        Auth::logout();
        request()->session()->invalidate();
        request()->session()->regenerateToken();

        return redirect('/');
    }
}
```

Routes:

```php
Route::get('/auth/synology', [SynologySsoController::class, 'redirect'])->name('synology.redirect');
Route::get('/auth/synology/callback', [SynologySsoController::class, 'callback'])->name('synology.callback');
Route::post('/logout', [SynologySsoController::class, 'logout'])->name('logout');
```

### With Rate Limiting

```php
Route::middleware(['throttle:10,1'])->group(function () {
    Route::get('/auth/synology', [SynologySsoController::class, 'redirect']);
    Route::get('/auth/synology/callback', [SynologySsoController::class, 'callback']);
});
```

---

## User Model Setup

### Database Migration

Add Synology ID column:

```bash
php artisan make:migration add_synology_fields_to_users_table
```

```php
public function up()
{
    Schema::table('users', function (Blueprint $table) {
        $table->string('synology_id')->nullable()->unique();
    });
}
```

```bash
php artisan migrate
```

### User Model

Update `app/Models/User.php`:

```php
protected $fillable = [
    'name',
    'email',
    'synology_id',
];
```

### With Role Management (spatie/laravel-permission)

```bash
composer require spatie/laravel-permission
php artisan vendor:publish --provider="Spatie\Permission\PermissionServiceProvider"
php artisan migrate
```

Update controller callback:

```php
$user->syncRoles($roles); // Sync roles from group mappings
```

---

## Advanced Configuration

### Custom User Model

```php
// config/synology-sso.php
'user_model' => App\Models\CustomUser::class,
```

### Disable Auto-Create Users

```php
'auto_create_users' => false,
```

Users must exist before SSO login.

### Custom Scopes

```php
// In your controller
return Socialite::driver('synology')
    ->scopes(['openid', 'email', 'groups', 'profile'])
    ->redirect();
```

### Development with Self-Signed Certificates

```env
SYNOLOGY_SSO_VERIFY_SSL=false
```

**⚠️ Never use in production!**

---

## Troubleshooting

### Issue: "redirect_uri_mismatch"

**Cause:** Redirect URI doesn't match Synology SSO configuration exactly.

**Solution:**
1. Check `.env`: `SYNOLOGY_SSO_REDIRECT_URI`
2. Verify in Synology SSO Server > Application Portal
3. Ensure exact match (including trailing slash, protocol, port)

### Issue: "Invalid state"

**Cause:** CSRF state parameter mismatch (common with multiple tabs).

**Solution:**
- Ensure cookies are enabled
- Check session configuration
- Don't open multiple login tabs

### Issue: "Token expired"

**Cause:** 180-second default token lifetime.

**Solution:** [Extend token lifetime](#extending-token-lifetime)

### Issue: "SSL certificate problem"

**Cause:** Self-signed certificate in development.

**Solution:**
```env
SYNOLOGY_SSO_VERIFY_SSL=false
```

### Issue: User not getting correct role

**Cause:** Group mapping mismatch.

**Solution:**
1. Check user's groups in Synology: Control Panel > User & Group
2. Verify group format:
   - Without Domain/LDAP: `admins`, `users`
   - With Domain/LDAP: `admins@example.com`, `users@example.com`
3. Check `config/synology-sso.php` mappings match your setup
4. Remember: Synology default groups are `admins` and `users` (not "administrators")

### Debug Mode

Enable Laravel debug mode:

```env
APP_DEBUG=true
```

Check logs:
```bash
tail -f storage/logs/laravel.log
```

---

## Next Steps

- Review [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- Read [SYNOLOGY_QUIRKS.md](SYNOLOGY_QUIRKS.md)
- Check [README.md](../README.md) for examples

---

**Need help?** Open an issue: https://github.com/Deroy2112/laravel-synology-sso/issues
