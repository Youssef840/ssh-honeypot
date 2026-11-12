# Screenshots

| File | Shows |
|---|---|
| `dashboard.png` | Overview page (KPIs, 24 h timeline, behaviour tags, top attacker IPs) |
| `session.png` | Session replay with behaviour tags |

Both were captured from `python scripts/demo.py`, which only uses RFC 5737 documentation
IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — no real attacker data.

To regenerate them after UI changes, run the demo and capture the page at 1440 px width
(e.g. with your browser's "Capture full size screenshot" devtools command).
Never publish screenshots containing real attacker IPs you have not anonymised.
