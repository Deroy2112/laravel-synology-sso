<?php

namespace Deroy2112\LaravelSynologySso;

use Deroy2112\LaravelSynologySso\Exceptions\UserProvisioningException;
use Illuminate\Database\Eloquent\Model;
use Laravel\Socialite\Contracts\User as SocialiteUser;

/**
 * Just-in-time provisioning of local users from authenticated Synology SSO
 * users. Finds an existing user by email and updates it, or creates one when
 * auto-creation is enabled. Role assignment is intentionally left to the
 * consumer (via GroupRoleMapper), since Laravel has no built-in role system.
 */
class UserProvisioner
{
    /**
     * Find, update, or just-in-time create the local user for an SSO user.
     *
     * @throws UserProvisioningException
     */
    public function provision(SocialiteUser $user): Model
    {
        $email = $user->getEmail();

        if (empty($email)) {
            throw new UserProvisioningException('Cannot provision a user without an email address');
        }

        $model = $this->userModel();
        $attributes = $this->mapAttributes($user);

        $existing = $model::query()->where('email', $email)->first();

        if ($existing !== null) {
            $existing->fill($attributes)->save();

            return $existing;
        }

        if (!config('synology-sso.auto_create_users', true)) {
            throw new UserProvisioningException(
                "No local user exists for [{$email}] and auto-creation is disabled"
            );
        }

        return $model::query()->create($attributes);
    }

    /**
     * Resolve and validate the configured Eloquent user model.
     *
     * @return class-string<Model>
     * @throws UserProvisioningException
     */
    protected function userModel(): string
    {
        $model = config('synology-sso.user_model', 'App\\Models\\User');

        if (!is_string($model) || !class_exists($model) || !is_subclass_of($model, Model::class)) {
            throw new UserProvisioningException(
                'Configured synology-sso.user_model is not a valid Eloquent model'
            );
        }

        return $model;
    }

    /**
     * Map SSO user fields to local model attributes. Only the standard OIDC
     * claims are mapped; anything else is the consumer's responsibility.
     *
     * @return array<string, mixed>
     */
    protected function mapAttributes(SocialiteUser $user): array
    {
        return array_filter([
            'email' => $user->getEmail(),
            'name' => $user->getName(),
        ], static fn ($value): bool => $value !== null);
    }
}
