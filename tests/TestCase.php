<?php

namespace Deroy2112\LaravelSynologySso\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \Laravel\Socialite\SocialiteServiceProvider::class,
            \Deroy2112\LaravelSynologySso\SynologySsoServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Setup default configuration
        $app['config']->set('synology-sso.host', 'https://sso.example.com');
        $app['config']->set('synology-sso.client_id', 'test-client-id');
        $app['config']->set('synology-sso.client_secret', 'test-client-secret');
        $app['config']->set('synology-sso.redirect_uri', 'https://app.example.com/callback');
        $app['config']->set('synology-sso.verify_ssl', false);
    }
}
