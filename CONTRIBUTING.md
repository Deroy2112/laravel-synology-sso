# Contributing

Thanks for helping out. This is a small, focused package, so the process is light.

## Development

```bash
git clone https://github.com/YOUR-USERNAME/laravel-synology-sso.git
cd laravel-synology-sso
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse src --level=5
```

Work on a feature branch and open a pull request against `main`. For anything
non-trivial, open an issue first so we can agree on the approach.

## Expectations

- Follow PSR-12; use strict types and return types.
- Every behaviour change needs a test. Tests are black-box and live in `tests/`.
- Keep `vendor/bin/phpunit` and `vendor/bin/phpstan analyse src` green.
- Update `CHANGELOG.md` (Keep a Changelog format) and, if relevant, the README.
- Use Conventional Commit messages (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Scope

In scope: the Synology SSO OIDC driver, PKCE, ID token verification, group-to-role
mapping, auto-discovery, and Synology-specific quirks. Out of scope: generic OAuth
providers, rate limiting, session management, 2FA — those belong in your app or
Laravel itself.

## Releases (maintainers)

1. Update `CHANGELOG.md`.
2. Tag the release: `git tag -a v1.2.0 -m "Release v1.2.0"`.
3. Push the tag: `git push origin v1.2.0`.
4. Create the GitHub release. Packagist picks it up via webhook.

The version is derived from the git tag — do not add a `version` field to
`composer.json`.

## Security

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/Deroy2112/laravel-synology-sso/security/advisories/new),
not public issues.
