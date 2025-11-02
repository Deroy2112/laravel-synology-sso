<?php

namespace Deroy2112\LaravelSynologySso;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Deroy2112\LaravelSynologySso\Console\InstallCommand;

class SynologySsoServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/synology-sso.php',
            'synology-sso'
        );

        $this->app->singleton(GroupRoleMapper::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Publish configuration file
        $this->publishes([
            __DIR__ . '/../config/synology-sso.php' => config_path('synology-sso.php'),
        ], 'synology-sso-config');

        // Publish documentation
        $this->publishes([
            __DIR__ . '/../docs' => base_path('docs/synology-sso'),
        ], 'synology-sso-docs');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
            ]);
        }

        // Register Socialite driver
        $this->bootSocialiteDriver();
    }

    /**
     * Bootstrap the Socialite driver.
     */
    protected function bootSocialiteDriver(): void
    {
        Socialite::extend('synology', function ($app) {
            $config = $app['config']['synology-sso'];

            return Socialite::buildProvider(SynologySocialiteDriver::class, [
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'redirect' => $config['redirect_uri'],
            ]);
        });
    }
}
