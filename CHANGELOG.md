# Changelog

All notable changes to `laravel-synology-sso` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-11-14

### Added
- Laravel Boost guideline for AI-assisted development
- Code snippets for routes registration, controller implementation, GroupRoleMapper API, and configuration
- Helps developers integrate the package using AI tools like Claude Code and Cursor

## [1.0.3] - 2025-11-14

### Fixed
- Added missing `--force` option to `synology-sso:install` command signature
- The command was using `$this->option('force')` but the option was not defined, causing it to always return null

## [1.0.2] - 2025-11-13

### Fixed
- Corrected all example URLs to include the complete `/webman/sso` path
- Updated `sso.example.com` to `sso.example.com/webman/sso` throughout documentation and tests

### Added
- User-friendly instructions for finding the SSO host URL from Synology DSM UI
- "Finding Your Synology SSO Host URL" section in README.md
- Helpful tips in docs/CONFIGURATION.md (multiple locations)
- Setup instructions displayed by `php artisan synology-sso:install` command

### Changed
- Updated all test configurations to use correct URL format with `/webman/sso` path

## [1.0.1] - 2025-11-13

### Fixed
- Corrected Synology SSO default group names from "admins" to "administrators" throughout the project
- Updated group name examples in README.md, configuration, and all documentation files
- Fixed group mapping examples and comments in config/synology-sso.php
- Corrected PHPDoc examples in src/GroupRoleMapper.php
- Updated install command output with correct group names
- Fixed all test fixtures with correct default group names

### Note
- This change affects documentation, comments, and test fixtures only
- No functional code logic changes
- The correct default groups are "administrators" and "users"

## [1.0.0] - 2025-11-13

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

[Unreleased]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Deroy2112/laravel-synology-sso/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Deroy2112/laravel-synology-sso/releases/tag/v1.0.0
