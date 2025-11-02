# Changelog

All notable changes to `laravel-synology-sso` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release
- Socialite driver for Synology SSO Server
- PKCE S256 implementation (RFC 7636 compliant)
- ID token verification with JWKS and RS256
- OIDC auto-discovery support
- Group-to-role mapping functionality
- JIT (Just-In-Time) user provisioning
- Comprehensive documentation (SYNOLOGY_QUIRKS.md, SECURITY_CHECKLIST.md, CONFIGURATION.md)
- Installation command (`php artisan synology-sso:install`)
- Support for Laravel 11.x and 12.x
- Support for PHP 8.2, 8.3, and 8.4
- Unit tests for core functionality
- GitHub Actions CI/CD pipeline
- Token lifetime extension guide for Synology DSM

### Security
- PKCE S256 for authorization code flow
- State parameter for CSRF protection
- ID token signature verification
- SSL certificate verification (configurable)
- Secure session-based token storage

## [1.0.0] - YYYY-MM-DD

### Added
- First stable release

[Unreleased]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Deroy2112/laravel-synology-sso/releases/tag/v1.0.0
