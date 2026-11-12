# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting instead: **Security → Advisories → Report a vulnerability**
on this repository. Include steps to reproduce, the affected version, and impact.
You can expect an acknowledgement within 7 days.

Examples of issues we care about:

- Any path by which attacker input reaches a real shell, the real file system or the network
- Escaping the fake shell's resource limits (memory, recursion, time)
- XSS / injection in the dashboard from attacker-controlled strings
- The honeypot being usable as a proxy or relay

## Operator responsibilities

This software is **designed to be attacked**. Run it only on isolated, disposable infrastructure
you own or are authorised to use, and follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
Captured credentials and IP addresses may be personal data in your jurisdiction — store them
securely and set `HP_RETENTION_DAYS`.
