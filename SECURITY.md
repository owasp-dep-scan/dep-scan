# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 5.x.x   | :white_check_mark: |
| 4.x.x   | :x:                |
| < 4.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use GitHub's private vulnerability reporting feature
3. Include detailed information about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Depends on severity and complexity

### Recognition

We appreciate responsible disclosure and will acknowledge contributors who report valid security issues (unless they prefer to remain anonymous).

## Security Best Practices

When using dep-scan:

1. Keep dep-scan updated to the latest version
2. Use in isolated environments when scanning untrusted code
3. Review scan results before taking automated actions
4. Integrate with your CI/CD pipeline for continuous security monitoring
