# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.2   | :white_check_mark: |
| < 1.1.1 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in FORTRESS PRIME, **please do not open a public issue**.  
Instead, report it privately via GitHub Security Advisories:

1. Go to the **Security** tab of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details and submit.

The author will respond within **72 hours** and will work with you to understand, reproduce, and fix the issue.  
Once a fix is ready, we will publish a security advisory alongside the patch release.

We appreciate responsible disclosure and will acknowledge your contribution (with your permission) when the advisory is published.

## Scope

This policy applies to:

- The main hardening script (`fortress_prime.py`)
- Any official release artifacts attached to GitHub Releases
- The project's CI/CD configuration

It does **not** cover:

- Issues in third‑party tools the script installs (report those upstream)
- Hardening configurations that are correct but differ from your personal preferences
- Feature requests disguised as security issues

## Hall of Fame

I maintain a list of individuals who have responsibly disclosed vulnerabilities to this project.  
To be added, just let us know in your report.
