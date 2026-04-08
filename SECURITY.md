# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | Yes                |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in Nyx, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisories (preferred):** Open a private advisory at
   [github.com/shadowm82/nyx/security/advisories/new](https://github.com/shadowm82/nyx/security/advisories/new)
2. **Email:** Send details to the repository owner via their GitHub profile.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Depends on severity; critical issues are prioritized

## Security Considerations

- Always run Nyx behind a reverse proxy with TLS in production.
- Rotate `NYX_SECRET_KEY` and `NYX_API_KEY` periodically.
- Never expose the database port to the public internet.
- Review the [production deployment](README.md#production-deployment) guide before going live.
