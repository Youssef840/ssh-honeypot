# Safe deployment guide

A honeypot is *meant* to be attacked. Treat the host as hostile and disposable.

## 1. Pick an isolated host

- A cheap VPS or a dedicated VM — **never** your laptop, a production server, or a machine on your office/home LAN.
- Nothing of value on it: no credentials, no SSH keys to other systems, no shared storage.

## 2. Move the real SSH daemon first

Edit `/etc/ssh/sshd_config`:

```
Port 22222
PasswordAuthentication no
PermitRootLogin no
```

```bash
sudo systemctl restart ssh
```

**Open a second terminal and confirm `ssh -p 22222 you@host` works before closing your current session.**

## 3a. Run with Docker (recommended)

```bash
git clone https://github.com/Youssef840/ssh-honeypot.git && cd ssh-honeypot
cp .env.example .env
nano .env                      # set DASH_PASSWORD to a long random value
docker compose up -d --build
docker compose logs -f honeypot
```

The container runs as UID 10001 with a read-only filesystem and no Linux capabilities.

## 3b. Run with systemd (without Docker)

```bash
sudo useradd -r -m -d /opt/honeypot -s /usr/sbin/nologin honeypot
sudo -u honeypot git clone https://github.com/Youssef840/ssh-honeypot.git /opt/honeypot/app
cd /opt/honeypot/app
sudo -u honeypot python3 -m venv .venv
sudo -u honeypot .venv/bin/pip install .
sudo -u honeypot cp .env.example .env
sudo -u honeypot mkdir -p data        # must exist for systemd's ReadWritePaths
```

Redirect port 22 to the unprivileged port 2222 (the honeypot never needs root):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo apt install iptables-persistent    # keep the rule after reboot
```

`/etc/systemd/system/ssh-honeypot.service`:

```ini
[Unit]
Description=SSH honeypot
After=network-online.target

[Service]
User=honeypot
WorkingDirectory=/opt/honeypot/app
Environment=HP_BIND_HOST=0.0.0.0
ExecStart=/opt/honeypot/app/.venv/bin/ssh-honeypot
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/honeypot/app/data
PrivateTmp=yes
CapabilityBoundingSet=
MemoryMax=256M

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-honeypot
```

Create a matching `ssh-honeypot-dashboard.service` with `ExecStart=…/ssh-honeypot-dashboard`.

## 4. Never expose the dashboard publicly

Keep `DASH_HOST=127.0.0.1` and reach it through an SSH tunnel:

```bash
ssh -p 22222 -L 5000:127.0.0.1:5000 you@your-vps
```

Then open http://127.0.0.1:5000 on your own machine.

## 5. Restrict outbound traffic

The emulator never makes network connections, but defence in depth helps:

```bash
sudo ufw default deny outgoing
sudo ufw allow out 53       # DNS
sudo ufw allow out 80,443/tcp   # OS updates
sudo ufw allow 22/tcp
sudo ufw allow 22222/tcp
sudo ufw enable
```

## 6. Operate

- Set `HP_RETENTION_DAYS=90` (or run `python -m honeypot --prune-days 90` from cron).
- `honeypot.log` rotates automatically (10 MB × 5). Rotate `events.jsonl` with `logrotate` if you keep it.
- Back up `data/host_rsa.key` — losing it changes the fingerprint returning bots see.
- Report abusive IPs to AbuseIPDB or the hosting provider. Never "hack back".

## Legal note

Only deploy on infrastructure you own or are explicitly authorised to use. Captured IPs and
credentials may be personal data under laws such as GDPR — store them securely and limit retention.
