# Contributing to Laravel Synology SSO

Thank you for considering contributing to Laravel Synology SSO! This document outlines the process for contributing to this project.

## Code of Conduct

This project adheres to a simple code of conduct:

- Be respectful and constructive in discussions
- Focus on the technical aspects of the contribution
- Help maintain a welcoming environment for all contributors

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report:

1. **Check existing issues** - Your bug may already be reported
2. **Test with the latest version** - The bug may already be fixed
3. **Verify it's not a Synology SSO Server issue** - Test the SSO server directly

When creating a bug report, include:

- **Title**: Clear and descriptive
- **Description**: Detailed steps to reproduce
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**:
  - Laravel version
  - PHP version
  - Synology DSM version
  - SSO Server version
  - Package version
- **Configuration**: Relevant config (redact secrets!)
- **Logs**: Error messages and stack traces

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:

1. **Check existing feature requests** - It may already be proposed
2. **Provide use case** - Explain why this would be useful
3. **Consider scope** - Should it be in this package or the application?
4. **Propose implementation** - If you have technical ideas

### Pull Requests

#### Before You Start

1. **Open an issue first** for significant changes
2. **Check if someone is already working on it**
3. **Discuss the approach** with maintainers

#### Development Setup

1. **Fork the repository**

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/laravel-synology-sso.git
   cd laravel-synology-sso
   ```

3. **Install dependencies**
   ```bash
   composer install
   ```

4. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

#### Coding Standards

- **PSR-12**: Follow PSR-12 coding standards
- **Type hints**: Use strict types and return type declarations
- **DocBlocks**: Document all public methods
- **Naming**: Use clear, descriptive names
- **KISS principle**: Keep it simple and straightforward

**Example:**
```php
<?php

namespace Deroy2112\LaravelSynologySso;

/**
 * Maps Synology SSO groups to Laravel roles.
 */
class GroupRoleMapper
{
    /**
     * Map groups to roles.
     *
     * @param array $groups Synology groups
     * @return array Mapped roles
     */
    public function mapGroupsToRoles(array $groups): array
    {
        // Implementation
    }
}
```

#### Writing Tests

All new features and bug fixes must include tests.

**Test structure:**
```
tests/
├── Unit/           # Unit tests (isolated, fast)
├── Feature/        # Feature tests (integration)
└── TestCase.php    # Base test class
```

**Run tests:**
```bash
composer test
# or
vendor/bin/phpunit
```

**Test coverage:**
```bash
vendor/bin/phpunit --coverage-html build/coverage
```

Aim for >80% code coverage for new code.

#### Writing Documentation

Documentation is as important as code!

- **Code comments**: Explain *why*, not *what*
- **README.md**: Update if adding features
- **Docs**: Update `docs/` for significant changes
- **Examples**: Provide usage examples
- **Changelog**: Add entry to CHANGELOG.md

#### Commit Messages

Use clear, descriptive commit messages:

**Format:**
```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat: Add support for custom OIDC scopes

Allow developers to override default scopes (openid, email, groups)
via configuration or method chaining.

Closes #123
```

```
fix: Correct PKCE challenge encoding

The base64url encoding was missing padding removal, causing
authentication failures with strict OIDC servers.

Fixes #456
```

#### Pull Request Process

1. **Update documentation** - README, docs/, CHANGELOG.md
2. **Add/update tests** - Ensure all tests pass
3. **Run code quality checks**:
   ```bash
   composer test
   # If available:
   composer phpstan
   composer format
   ```

4. **Create pull request**:
   - Clear title describing the change
   - Reference related issues
   - Describe what changed and why
   - Include screenshots for UI changes
   - List any breaking changes

5. **Respond to feedback** - Address review comments promptly

6. **Squash commits** (if requested) - Keep history clean

#### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Related Issues
Closes #123

## Changes Made
- Added X feature
- Fixed Y bug
- Updated Z documentation

## Testing
- [ ] Unit tests added/updated
- [ ] Feature tests added/updated
- [ ] All tests passing
- [ ] Manual testing completed

## Checklist
- [ ] Code follows PSR-12 standards
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added with >80% coverage
- [ ] CHANGELOG.md updated
```

## Package Scope

This package focuses on **Synology SSO integration only**. The following are **out of scope**:

### Out of Scope
- General OAuth/OIDC providers (use Laravel Socialite)
- Application-specific features (user dashboards, etc.)
- Rate limiting (use Laravel middleware)
- Session management (use Laravel sessions)
- Login history tracking (application concern)
- Two-factor authentication (separate package)

### In Scope
- Synology SSO OIDC driver
- PKCE implementation
- ID token verification
- Group-to-role mapping
- OIDC auto-discovery
- Synology-specific quirks handling

When in doubt, open an issue to discuss scope.

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

**Instead:**
- Email: [Add your security email]
- Include: Detailed description, reproduction steps, impact
- Allow reasonable time for patching before disclosure

## Development Guidelines

### Package Philosophy

- **Minimalist**: Only Synology-specific features
- **Laravel-native**: Use Laravel conventions and features
- **Well-documented**: Clear docs for Synology quirks
- **Tested**: High test coverage
- **Secure**: Security best practices

### Code Review Checklist

Before submitting:

- [ ] Does it follow package philosophy?
- [ ] Is it well-tested?
- [ ] Is it documented?
- [ ] Does it maintain backward compatibility?
- [ ] Is it secure?
- [ ] Is it performant?
- [ ] Does it handle errors gracefully?

## Release Process

(For maintainers)

1. Update CHANGELOG.md
2. Update version in composer.json
3. Tag release: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. Create GitHub release with changelog
6. Packagist auto-updates

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email security contact
- **Chat**: [Add Discord/Slack if available]

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Laravel Synology SSO! 🚀
