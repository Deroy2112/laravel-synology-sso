<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Deroy2112\LaravelSynologySso\GroupRoleMapper;
use Orchestra\Testbench\TestCase;

class GroupRoleMapperTest extends TestCase
{
    protected GroupRoleMapper $mapper;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mapper = new GroupRoleMapper();
    }

    protected function getPackageProviders($app)
    {
        return [
            \Laravel\Socialite\SocialiteServiceProvider::class,
            \Deroy2112\LaravelSynologySso\SynologySsoServiceProvider::class,
        ];
    }

    /** @test */
    public function it_maps_single_group_to_single_role()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
            ],
        ]);

        $groups = ['administrators@example.com'];
        $roles = $this->mapper->mapGroupsToRoles($groups);

        $this->assertEquals(['admin'], $roles);
    }

    /** @test */
    public function it_maps_multiple_groups_to_multiple_roles()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
                'users@example.com' => 'user',
            ],
        ]);

        $groups = ['administrators@example.com', 'users@example.com'];
        $roles = $this->mapper->mapGroupsToRoles($groups);

        $this->assertEqualsCanonicalizing(['admin', 'user'], $roles);
    }

    /** @test */
    public function it_maps_single_group_to_multiple_roles()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => ['admin', 'user'],
            ],
        ]);

        $groups = ['administrators@example.com'];
        $roles = $this->mapper->mapGroupsToRoles($groups);

        $this->assertEqualsCanonicalizing(['admin', 'user'], $roles);
    }

    /** @test */
    public function it_returns_empty_array_for_unmapped_groups()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
            ],
        ]);

        $groups = ['unknown@example.com'];
        $roles = $this->mapper->mapGroupsToRoles($groups);

        $this->assertEquals([], $roles);
    }

    /** @test */
    public function it_returns_unique_roles()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => ['admin', 'user'],
                'users@example.com' => 'user',
            ],
        ]);

        $groups = ['administrators@example.com', 'users@example.com'];
        $roles = $this->mapper->mapGroupsToRoles($groups);

        // Should only have 'admin' and 'user' once
        $this->assertCount(2, $roles);
        $this->assertContains('admin', $roles);
        $this->assertContains('user', $roles);
    }

    /** @test */
    public function it_gets_primary_role_from_groups()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
                'users@example.com' => 'user',
            ],
            'synology-sso.role_priority' => ['admin', 'user'],
        ]);

        $groups = ['users@example.com', 'administrators@example.com'];
        $primaryRole = $this->mapper->getPrimaryRole($groups);

        $this->assertEquals('admin', $primaryRole);
    }

    /** @test */
    public function it_returns_default_role_when_no_groups_matched()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
            ],
            'synology-sso.default_role' => 'guest',
        ]);

        $groups = ['unknown@example.com'];
        $primaryRole = $this->mapper->getPrimaryRole($groups);

        $this->assertEquals('guest', $primaryRole);
    }

    /** @test */
    public function it_returns_null_when_no_default_role_set()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
            ],
            'synology-sso.default_role' => null,
        ]);

        $groups = ['unknown@example.com'];
        $primaryRole = $this->mapper->getPrimaryRole($groups);

        $this->assertNull($primaryRole);
    }

    /** @test */
    public function it_checks_if_user_has_required_group()
    {
        $userGroups = ['administrators@example.com', 'users@example.com'];
        $requiredGroups = ['administrators@example.com'];

        $hasGroup = $this->mapper->hasRequiredGroup($userGroups, $requiredGroups);

        $this->assertTrue($hasGroup);
    }

    /** @test */
    public function it_returns_false_when_user_lacks_required_group()
    {
        $userGroups = ['users@example.com'];
        $requiredGroups = ['administrators@example.com'];

        $hasGroup = $this->mapper->hasRequiredGroup($userGroups, $requiredGroups);

        $this->assertFalse($hasGroup);
    }

    /** @test */
    public function it_grants_access_when_no_allowed_groups_configured()
    {
        config(['synology-sso.allowed_groups' => []]);

        $userGroups = ['anything@example.com'];
        $hasAccess = $this->mapper->hasAccess($userGroups);

        $this->assertTrue($hasAccess);
    }

    /** @test */
    public function it_grants_access_when_user_has_allowed_group()
    {
        config([
            'synology-sso.allowed_groups' => ['administrators@example.com', 'users@example.com'],
        ]);

        $userGroups = ['users@example.com'];
        $hasAccess = $this->mapper->hasAccess($userGroups);

        $this->assertTrue($hasAccess);
    }

    /** @test */
    public function it_denies_access_when_user_lacks_allowed_group()
    {
        config([
            'synology-sso.allowed_groups' => ['administrators@example.com'],
        ]);

        $userGroups = ['users@example.com'];
        $hasAccess = $this->mapper->hasAccess($userGroups);

        $this->assertFalse($hasAccess);
    }

    /** @test */
    public function it_gets_all_roles_with_primary_first()
    {
        config([
            'synology-sso.group_role_mappings' => [
                'administrators@example.com' => 'admin',
                'users@example.com' => 'user',
            ],
            'synology-sso.role_priority' => ['admin', 'user'],
        ]);

        $groups = ['users@example.com', 'administrators@example.com'];
        $allRoles = $this->mapper->getAllRoles($groups);

        // Primary role (admin) should be first
        $this->assertEquals('admin', $allRoles[0]);
        $this->assertContains('user', $allRoles);
    }
}
