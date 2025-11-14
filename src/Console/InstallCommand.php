<?php

namespace Deroy2112\LaravelSynologySso\Console;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'synology-sso:install {--force : Overwrite existing files}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install Synology SSO package (publish config and docs)';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info('Installing Laravel Synology SSO...');

        // Publish configuration
        $this->call('vendor:publish', [
            '--tag' => 'synology-sso-config',
            '--force' => $this->option('force'),
        ]);

        $this->info('Configuration published!');

        // Ask if user wants documentation
        if ($this->confirm('Publish documentation to docs/synology-sso?', true)) {
            $this->call('vendor:publish', [
                '--tag' => 'synology-sso-docs',
                '--force' => $this->option('force'),
            ]);
            $this->info('Documentation published!');
        }

        // Display environment variables template
        $this->displayEnvTemplate();

        $this->newLine();
        $this->info('✓ Laravel Synology SSO installed successfully!');
        $this->newLine();
        $this->info('Next steps:');
        $this->line('1. Add the environment variables shown above to your .env file');
        $this->line('2. Configure OAuth application in Synology SSO Server');
        $this->line('3. Add authentication routes (see README.md)');
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Display environment variables template.
     *
     * @return void
     */
    protected function displayEnvTemplate(): void
    {
        $this->newLine();
        $this->info('Finding your SYNOLOGY_SSO_HOST value:');
        $this->line('1. Open DSM > SSO Server > Services > OIDC');
        $this->line('2. Copy the "Well-Known URL"');
        $this->line('3. Remove "/.well-known/openid-configuration" from the end');
        $this->line('4. Use the remaining URL (e.g., https://sso.example.com/webman/sso)');
        $this->newLine();
        $this->info('Add these variables to your .env file:');
        $this->newLine();

        $envTemplate = <<<'ENV'
# Synology SSO Configuration
SYNOLOGY_SSO_HOST=https://sso.example.com/webman/sso
SYNOLOGY_SSO_CLIENT_ID=your-client-id
SYNOLOGY_SSO_CLIENT_SECRET=your-client-secret
SYNOLOGY_SSO_REDIRECT_URI="${APP_URL}/auth/synology/callback"

# Optional: Group to Role Mappings (Synology defaults: "administrators" and "users")
# Without Domain/LDAP:
# SYNOLOGY_SSO_ADMIN_GROUP=administrators
# SYNOLOGY_SSO_USER_GROUP=users
# With Domain/LDAP:
# SYNOLOGY_SSO_ADMIN_GROUP=administrators@example.com
# SYNOLOGY_SSO_USER_GROUP=users@example.com

# Optional: Default role for users without group mapping
SYNOLOGY_SSO_DEFAULT_ROLE=user

# Optional: Auto-create users on first login (JIT provisioning)
SYNOLOGY_SSO_AUTO_CREATE_USERS=true

# Optional: SSL verification (disable only for development with self-signed certs)
SYNOLOGY_SSO_VERIFY_SSL=true
ENV;

        $this->line($envTemplate);
    }
}
