<?php

namespace Deroy2112\LaravelSynologySso\Tests\Unit;

use Deroy2112\LaravelSynologySso\Exceptions\UserProvisioningException;
use Deroy2112\LaravelSynologySso\Tests\Support\TestUser;
use Deroy2112\LaravelSynologySso\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Two\User as SocialiteUser;
use PHPUnit\Framework\Attributes\Test;

/**
 * Black-box tests for just-in-time user provisioning against a real in-memory
 * SQLite database and a stand-in Eloquent model.
 */
class UserProvisionerTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('synology-sso.user_model', TestUser::class);
        $app['config']->set('synology-sso.auto_create_users', true);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->unique();
            $table->timestamps();
        });
    }

    private function ssoUser(?string $email, ?string $name): SocialiteUser
    {
        return (new SocialiteUser())->map([
            'email' => $email,
            'name' => $name,
        ]);
    }

    private function provisioner(): \Deroy2112\LaravelSynologySso\UserProvisioner
    {
        return $this->app->make(\Deroy2112\LaravelSynologySso\UserProvisioner::class);
    }

    #[Test]
    public function it_creates_a_new_user_when_none_exists(): void
    {
        $user = $this->provisioner()->provision($this->ssoUser('jane@example.com', 'Jane Doe'));

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame('jane@example.com', $user->email);
        $this->assertSame('Jane Doe', $user->name);
        $this->assertSame(1, TestUser::query()->count());
    }

    #[Test]
    public function it_updates_an_existing_user_instead_of_duplicating(): void
    {
        TestUser::query()->create(['email' => 'jane@example.com', 'name' => 'Old Name']);

        $user = $this->provisioner()->provision($this->ssoUser('jane@example.com', 'New Name'));

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame('New Name', $user->name);
        $this->assertSame(1, TestUser::query()->count());
    }

    #[Test]
    public function it_rejects_an_unknown_user_when_auto_creation_is_disabled(): void
    {
        config(['synology-sso.auto_create_users' => false]);

        $this->expectException(UserProvisioningException::class);
        $this->expectExceptionMessage('auto-creation is disabled');

        $this->provisioner()->provision($this->ssoUser('ghost@example.com', 'Ghost'));
    }

    #[Test]
    public function it_updates_an_existing_user_even_when_auto_creation_is_disabled(): void
    {
        config(['synology-sso.auto_create_users' => false]);
        TestUser::query()->create(['email' => 'jane@example.com', 'name' => 'Old Name']);

        $user = $this->provisioner()->provision($this->ssoUser('jane@example.com', 'New Name'));

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertSame('New Name', $user->name);
    }

    #[Test]
    public function it_rejects_an_sso_user_without_an_email(): void
    {
        $this->expectException(UserProvisioningException::class);
        $this->expectExceptionMessage('without an email');

        $this->provisioner()->provision($this->ssoUser(null, 'No Email'));
    }
}
