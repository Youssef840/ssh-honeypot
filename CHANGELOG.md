# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-11

### Added
- Paramiko SSH honeypot engine: fake OpenSSH banner, persistent host key, password and
  public-key capture, configurable auth policy (`list`, `after_n`, `any`, `never`).
- Fake bash shell with in-memory file system, ~100 emulated commands, pipelines
  (grep/wc/head/tail/awk/cut/sort/uniq/tr), redirections and `base64 -d` payload decoding.
- Threat analysis: risk scoring, behaviour tags mapped to MITRE ATT&CK, URL/IP IOC extraction.
- SQLite storage (WAL, schema versioning, retention pruning) plus a JSON-lines event feed.
- Flask dashboard (Arabic RTL, light/dark): KPIs, attack timeline, top IPs with threat level,
  top usernames/passwords/commands, IOC list, session replay, per-IP profile, JSON API, CSV export.
- Abuse protection: per-IP and global connection caps, auth/idle/session timeouts,
  refused port forwarding and SFTP, bounded emulator recursion and memory.
- Docker image (non-root, read-only, no capabilities) and docker-compose stack.
- Behaviour-based threat levels (critical / high / medium / low) per attacker IP.
- `scripts/demo.py`: one-command demo with realistic seeded traffic and live SSH attacks.
- Test suite (unit + end-to-end over real SSH), GitHub Actions CI, CodeQL, Dependabot.

[Unreleased]: https://github.com/Youssef840/ssh-honeypot/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Youssef840/ssh-honeypot/releases/tag/v1.0.0
