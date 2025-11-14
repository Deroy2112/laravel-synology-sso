### Laravel Synology SSO

Laravel Socialite driver for Synology DSM SSO Server with OIDC, PKCE S256, ID token verification, and group-to-role mapping.

---

### Routes Setup

Register authentication routes in `routes/web.php`:

@verbatim
<code-snippet name="Authentication routes" lang="php">
use App\Http\Controllers\Auth\SynologySsoController;

Route::get('/auth/synology', [SynologySsoController::class, 'redirect'])->name('synology.redirect');
Route::get('/auth/synology/callback', [SynologySsoController::class, 'callback'])->name('synology.callback');
Route::post('/logout', [SynologySsoController::class, 'logout'])->name('logout');

// With rate limiting
Route::middleware(['throttle:10,1'])->group(function () {
    Route::get('/auth/synology', [SynologySsoController::class, 'redirect']);
    Route::get('/auth/synology/callback', [SynologySsoController::class, 'callback']);
});
</code-snippet>
@endverbatim

---

### Controller Implementation

Create `app/Http/Controllers/Auth/SynologySsoController.php`:

@verbatim
<code-snippet name="SSO Controller" lang="php">
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

            // Check access based on groups
            if (!$mapper->hasAccess($ssoUser->groups ?? [])) {
                abort(403, 'You do not have permission to access this application.');
            }

            // Find or create user (JIT provisioning)
            $user = User::updateOrCreate(
                ['email' => $ssoUser->email],
                [
                    'name' => $ssoUser->name,
                    'synology_id' => $ssoUser->id,
                ]
            );

            // Assign roles from groups
            $roles = $mapper->mapGroupsToRoles($ssoUser->groups ?? []);
            $user->syncRoles($roles); // Requires spatie/laravel-permission

            Auth::login($user, true);

            return redirect()->intended('/dashboard');

        } catch (\Exception $e) {
            report($e);
            return redirect('/login')->with('error', 'Authentication failed.');
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
</code-snippet>
@endverbatim

---

### GroupRoleMapper API

Use the `GroupRoleMapper` to map Synology groups to Laravel roles:

@verbatim
<code-snippet name="GroupRoleMapper usage" lang="php">
use Deroy2112\LaravelSynologySso\GroupRoleMapper;

$mapper = app(GroupRoleMapper::class);

// Map groups to roles
$roles = $mapper->mapGroupsToRoles(['administrators', 'users']);
// Returns: ['admin', 'user']

// Get primary role based on priority
$primaryRole = $mapper->getPrimaryRole(['administrators', 'users']);
// Returns: 'admin'

// Check if user has access
$hasAccess = $mapper->hasAccess(['administrators']);
// Returns: true/false

// Practical usage in controller
if (!$mapper->hasAccess($ssoUser->groups ?? [])) {
    abort(403, 'Access denied');
}

$roles = $mapper->mapGroupsToRoles($ssoUser->groups ?? []);
$user->syncRoles($roles);
</code-snippet>
@endverbatim

---

### Configuration

Configure group-to-role mappings in `config/synology-sso.php`:

@verbatim
<code-snippet name="Group-to-role mapping configuration" lang="php">
'group_role_mappings' => [
    // Standard Synology groups
    'administrators' => 'admin',
    'users' => 'user',

    // LDAP groups (with domain)
    'administrators@example.com' => 'admin',
    'users@example.com' => 'user',
],

// Default role for unmapped users
'default_role' => 'user', // Or null to deny access

// Role priority (for primary role selection)
'role_priority' => [
    'admin',
    'developer',
    'user',
],

// Restrict access to specific groups
'allowed_groups' => [], // Empty = allow all
</code-snippet>
@endverbatim

---

### User Data Structure

The `$ssoUser` object from `Socialite::driver('synology')->user()` provides:

- `$ssoUser->id` - Synology username (string)
- `$ssoUser->email` - Email address (string)
- `$ssoUser->name` - Display name (string)
- `$ssoUser->groups` - User groups (array)

**Group formats:**
- Without LDAP: `["administrators", "users"]`
- With LDAP: `["administrators@example.com", "users@example.com"]`

**User Model Setup:**
Add `synology_id` column to users table (nullable, unique). Update `$fillable` to include `'synology_id'`.

---

### Best Practices

- **URL Format**: Ensure `SYNOLOGY_SSO_HOST` includes `/webman/sso` path in `.env`
- **Redirect URI**: Must match exactly in Synology SSO configuration
- **HTTPS**: Always use HTTPS in production (`SYNOLOGY_SSO_VERIFY_SSL=true`)
- **Group Formats**: Support both standard and LDAP group formats in config
- **Access Control**: Use `$mapper->hasAccess()` before user creation
- **Error Handling**: Wrap callback logic in try-catch blocks

---

**Documentation**: https://github.com/Deroy2112/laravel-synology-sso
