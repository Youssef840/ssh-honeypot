"""
Threat analysis of attacker input.

Each command line typed by an attacker is matched against rules modelled on
common SSH-bot behaviour (categories loosely follow MITRE ATT&CK tactics).
The resulting score feeds the "most dangerous IPs" ranking and the behaviour
breakdown in the dashboard. URLs and bare IPs are extracted as IOCs
(Indicators of Compromise) so they can be investigated *without* the honeypot
ever contacting them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A command word must appear at the start of the line or right after a
# separator / wrapper, so that e.g. "--user-id" is not mistaken for `id`.
_CMD = r"(?:^|[;&|(`\n]\s*|\b(?:sudo|nohup|busybox|timeout\s+\d+)\s+)(?:[\w.~-]*/)*"

# (compiled regex, risk points, tag, MITRE ATT&CK technique)
RULES: list[tuple[re.Pattern[str], int, str, str]] = [
    (
        re.compile(r"(/dev/tcp/|/dev/udp/|\bnc(at)?\b[^|;]*\s-[a-z]*e\b|\bsocat\b|\bbash\s+-i\b|\bmkfifo\b)"),
        10,
        "reverse-shell",
        "T1059.004",
    ),
    (
        re.compile(r"\b(xmrig|minerd|cpuminer|nicehash|stratum\+tcp|cryptonight|monero)\b", re.I),
        10,
        "cryptominer",
        "T1496",
    ),
    (re.compile(_CMD + r"(wget|curl|tftp|ftpget|fetch|lwp-download)\b"), 8, "download", "T1105"),
    (
        re.compile(r"(base64\s+(-d|--decode)|\|\s*(ba|z|da)?sh\b|\beval\b|\bpython[23]?\s+-c\b|\bperl\s+-e\b)"),
        7,
        "obfuscated-exec",
        "T1027",
    ),
    (
        re.compile(r"(\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\bdd\s+if=|\bmkfs\b|\bshred\b)"),
        7,
        "destructive",
        "T1485",
    ),
    (
        re.compile(r"(authorized_keys|\bcrontab\b|/etc/cron|/etc/rc\.local|systemctl\s+enable|\.bashrc|\.profile)"),
        7,
        "persistence",
        "T1098.004",
    ),
    (re.compile(_CMD + r"(useradd|adduser|usermod|chpasswd|passwd)\b"), 6, "account-manipulation", "T1136"),
    (re.compile(r"\bchmod\s+(\S*\+x|[0-7]*[1357][0-7]{0,2}\b|777)"), 6, "make-executable", "T1222"),
    (
        re.compile(
            r"(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|\biptables\b|\bufw\b|setenforce\s+0"
            r"|\bpkill\b|\bkillall\b|\bchattr\b)"
        ),
        5,
        "defense-evasion",
        "T1562",
    ),
    (
        re.compile(r"(/etc/shadow|/etc/passwd|\.ssh/id_|\.aws/credentials|\.bash_history)"),
        4,
        "credential-access",
        "T1552",
    ),
    (
        re.compile(
            _CMD + r"(uname|nproc|lscpu|free|whoami|id|w|who|uptime|hostname|ifconfig|ip\s+a|lspci|dmidecode"
            r"|cat\s+/proc/(cpuinfo|meminfo|version)|getconf)\b"
        ),
        1,
        "recon",
        "T1082",
    ),
]

TAG_TECHNIQUES: dict[str, str] = {tag: technique for _, _, tag, technique in RULES}

URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>;|`)]+", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

MAX_RISK = 50


@dataclass(frozen=True)
class CommandAnalysis:
    risk: int
    tags: tuple[str, ...]
    techniques: tuple[str, ...]
    urls: tuple[str, ...]
    ips: tuple[str, ...]


def analyze_command(command: str) -> CommandAnalysis:
    """Score one command line (it may contain several `;`-separated commands)."""
    risk = 0
    tags: list[str] = []
    techniques: list[str] = []
    for pattern, points, tag, technique in RULES:
        if pattern.search(command):
            risk += points
            tags.append(tag)
            techniques.append(technique)
    urls = tuple(dict.fromkeys(URL_RE.findall(command)))
    # IPs that appear outside of URLs (e.g. `nc 1.2.3.4 4444`); skip loopback/unspecified
    stripped = URL_RE.sub(" ", command)
    ips = tuple(ip for ip in dict.fromkeys(IP_RE.findall(stripped)) if not ip.startswith(("127.", "0.")))
    return CommandAnalysis(risk=min(risk, MAX_RISK), tags=tuple(tags), techniques=tuple(techniques), urls=urls, ips=ips)
