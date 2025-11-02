<?php

namespace Deroy2112\LaravelSynologySso;

class GroupRoleMapper
{
    /**
     * Map Synology SSO groups to Laravel roles.
     *
     * @param array $groups Synology groups
     *                      Without Domain/LDAP: ["admins", "users"]
     *                      With Domain/LDAP:    ["admins@example.com", "users@example.com"]
     * @return array Mapped roles (e.g., ["admin", "user"])
     */
    public function mapGroupsToRoles(array $groups): array
    {
        $mappings = config('synology-sso.group_role_mappings', []);
        $roles = [];

        foreach ($groups as $group) {
            if (isset($mappings[$group])) {
                $role = $mappings[$group];

                // Support single role or array of roles
                if (is_array($role)) {
                    $roles = array_merge($roles, $role);
                } else {
                    $roles[] = $role;
                }
            }
        }

        return array_unique($roles);
    }

    /**
     * Get the primary (first) role from the mapped roles.
     *
     * @param array $groups Synology groups
     * @return string|null Primary role or default role
     */
    public function getPrimaryRole(array $groups): ?string
    {
        $roles = $this->mapGroupsToRoles($groups);

        if (empty($roles)) {
            return config('synology-sso.default_role');
        }

        // Return first role based on priority order in config
        $priorityOrder = config('synology-sso.role_priority', []);

        foreach ($priorityOrder as $priorityRole) {
            if (in_array($priorityRole, $roles)) {
                return $priorityRole;
            }
        }

        // If no priority match, return first role
        return $roles[0];
    }

    /**
     * Check if user has at least one required group.
     *
     * @param array $userGroups User's groups from Synology
     * @param array $requiredGroups Groups required for access
     * @return bool
     */
    public function hasRequiredGroup(array $userGroups, array $requiredGroups): bool
    {
        return !empty(array_intersect($userGroups, $requiredGroups));
    }

    /**
     * Check if user has access based on allowed groups configuration.
     *
     * @param array $userGroups User's groups from Synology
     * @return bool
     */
    public function hasAccess(array $userGroups): bool
    {
        $allowedGroups = config('synology-sso.allowed_groups');

        // If no allowed groups configured, grant access
        if (empty($allowedGroups)) {
            return true;
        }

        return $this->hasRequiredGroup($userGroups, $allowedGroups);
    }

    /**
     * Get all roles for a user based on their groups.
     *
     * @param array $groups Synology groups
     * @return array All roles with primary role first
     */
    public function getAllRoles(array $groups): array
    {
        $roles = $this->mapGroupsToRoles($groups);
        $primaryRole = $this->getPrimaryRole($groups);

        if ($primaryRole) {
            // Remove primary role if it exists
            $roles = array_diff($roles, [$primaryRole]);
            // Add primary role at the beginning
            array_unshift($roles, $primaryRole);
        }

        return array_values(array_unique($roles));
    }
}
