"""
Emulated Linux shell.

SAFETY CONTRACT
---------------
Nothing in this module ever touches the real operating system: there is no
``subprocess``, no ``os.system``, no real file I/O and no network access.
Every "command" is a pure Python function ``(args, stdin) -> str`` and the
file system is an in-memory dict that is discarded when the session ends.
``wget``/``curl`` are *simulated failures*; the caller only records the URL.

Realism features
----------------
* ``;``, ``&&``, ``||`` sequencing and ``|`` pipelines (grep, wc, head, tail,
  awk, cut, sort, uniq, tr, base64 -d, sh) — bots fingerprint hosts with
  pipelines such as ``cat /proc/cpuinfo | grep name | wc -l``.
* Redirections: ``>``, ``>>``, ``2>/dev/null``, ``2>&1``, ``&>``, ``<``, ``&``.
* ``$VAR`` / ``${VAR}`` expansion (unknown variables expand to empty, as bash).
* Decoded ``base64 -d`` payloads are exposed via :meth:`FakeShell.take_payloads`
  so the engine can log what an obfuscated command really contained.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import random
import re
import shlex
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

Handler = Callable[[list[str], str], str]

DIR = None  # marker value for directories in the virtual file system
MAX_FS_NODES = 2000
MAX_FILE_SIZE = 65536
MAX_DEPTH = 16
MAX_PAYLOAD = 4096


# --------------------------------------------------------------------------- #
# Virtual file system                                                          #
# --------------------------------------------------------------------------- #
def _cpuinfo() -> str:
    block = (
        "processor\t: {i}\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "cpu MHz\t\t: 2399.998\n"
        "cache size\t: 35840 KB\n"
        "cpu cores\t: 4\n\n"
    )
    return "".join(block.format(i=i) for i in range(4))


def _base_tree(hostname: str, username: str) -> dict[str, str | None]:
    home = "/root" if username == "root" else f"/home/{username}"
    dirs = [
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/etc/ssh",
        "/etc/cron.d",
        "/home",
        "/home/ubuntu",
        "/lib",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/root/.ssh",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/usr/bin",
        "/usr/local",
        "/usr/local/bin",
        "/usr/sbin",
        "/var",
        "/var/log",
        "/var/tmp",
        "/var/www",
        "/var/www/html",
        home,
    ]
    tree: dict[str, str | None] = dict.fromkeys(dirs, DIR)
    tree.update(
        {
            "/dev/null": "",
            "/etc/hostname": f"{hostname}\n",
            "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n\n",
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\n'
                'ID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\n'
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
                "mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            ),
            "/etc/shadow": (
                "root:$6$Vx3kq9Lp$2bW0e8nQ7Hc4sYtJ1mR6uZ5aF.dG3kL9pO2iU7yT1rE4wQ8xC0vB5nM6zA3sD1fG7hJ9kL2"
                ":19700:0:99999:7:::\n"
                "ubuntu:$6$Qm8vT2rX$9pL4kJ7hG2fD5sA1zX8cV3bN6mQ0wE4rT7yU2iO5pA8sD1fG4hJ7kL0zX3cV6bN9mQ2"
                ":19700:0:99999:7:::\n"
            ),
            "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nUsePAM yes\n",
            "/proc/version": (
                "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-007) "
                "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #115-Ubuntu SMP\n"
            ),
            "/proc/cpuinfo": _cpuinfo(),
            "/proc/meminfo": (
                "MemTotal:        8148132 kB\nMemFree:         5231048 kB\nMemAvailable:    6912340 kB\n"
                "SwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n"
            ),
            "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
            "/var/log/auth.log": "",
            "/home/ubuntu/.bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
            "/root/.bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
            "/root/.bash_history": "",
            "/root/.ssh/authorized_keys": "",
        }
    )
    return tree


class VirtualFS:
    """Tiny in-memory file system. Paths are absolute and normalised."""

    def __init__(self, hostname: str, username: str):
        self.nodes = _base_tree(hostname, username)

    def exists(self, path: str) -> bool:
        return path in self.nodes

    def isdir(self, path: str) -> bool:
        return path in self.nodes and self.nodes[path] is DIR

    def read(self, path: str) -> str | None:
        value = self.nodes.get(path)
        return value if isinstance(value, str) else None

    def write(self, path: str, content: str, append: bool = False) -> bool:
        if path == "/dev/null":
            return True
        if not self.isdir(posixpath.dirname(path)) or self.isdir(path):
            return False
        if path not in self.nodes and len(self.nodes) >= MAX_FS_NODES:
            return False  # cap the memory an attacker can make us consume
        old = self.read(path) or ""
        self.nodes[path] = (old + content if append else content)[:MAX_FILE_SIZE]
        return True

    def mkdir(self, path: str) -> bool:
        if self.exists(path) or not self.isdir(posixpath.dirname(path)) or len(self.nodes) >= MAX_FS_NODES:
            return False
        self.nodes[path] = DIR
        return True

    def remove(self, path: str) -> None:
        prefix = path.rstrip("/") + "/"
        for p in [p for p in self.nodes if p == path or p.startswith(prefix)]:
            if p != "/":
                del self.nodes[p]

    def listdir(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix) :].split("/")[0] for p in self.nodes if p.startswith(prefix) and p != path}
        return sorted(n for n in names if n)


# --------------------------------------------------------------------------- #
# Command-line parsing                                                         #
# --------------------------------------------------------------------------- #
def _split_unquoted(line: str, is_sep: Callable[[str, int], int]) -> list[str]:
    """Generic splitter: ``is_sep(line, i)`` returns the separator length at i (0 = none)."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch == "\\" and i + 1 < len(line):
            buf.append(line[i : i + 2])
            i += 2
            continue
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        else:
            n = is_sep(line, i)
            if n:
                parts.append("".join(buf))
                buf = []
                i += n
                continue
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def split_command_line(line: str) -> list[str]:
    """Split on ``;``, ``&&``, ``||`` and newlines, respecting quotes."""

    def sep(s: str, i: int) -> int:
        if s[i : i + 2] in ("&&", "||"):
            return 2
        return 1 if s[i] in ";\n" else 0

    return [p.strip() for p in _split_unquoted(line, sep) if p.strip()]


def split_pipeline(segment: str) -> list[str]:
    """Split a segment on single ``|`` (``||`` was already consumed)."""
    return [p.strip() for p in _split_unquoted(segment, lambda s, i: 1 if s[i] == "|" else 0)]


_VAR_RE = re.compile(r"\$\{(\w+)\}|\$([A-Za-z_]\w*)")


def tokenize(segment: str, env: dict[str, str] | None = None, home: str | None = None) -> list[str]:
    """Bash-like word splitting with quote-aware expansion.

    * ``'single'`` quotes: fully literal (so ``awk '{print $NF}'`` keeps ``$NF``)
    * ``"double"`` quotes: ``$VAR`` expanded, ``\\"`` escapes honoured
    * unquoted: ``$VAR`` and a leading ``~`` expanded, backslash escapes one char
    Unknown variables expand to the empty string. Unbalanced quotes never raise.
    When ``env`` is None no expansion is performed.
    """
    tokens: list[str] = []
    buf: list[str] = []
    in_word = False
    had_quote = False  # '' or "" yields an empty word; an empty unquoted $VAR yields none
    quote: str | None = None
    i, n = 0, len(segment)

    def flush() -> None:
        nonlocal buf, in_word, had_quote
        word = "".join(buf)
        if in_word and (word or had_quote):
            tokens.append(word)
        buf, in_word, had_quote = [], False, False

    def expand_at(pos: int) -> tuple[int, str]:
        m = _VAR_RE.match(segment, pos)
        if env is None or not m:
            return 1, "$"
        return m.end() - pos, env.get(m.group(1) or m.group(2), "")

    while i < n:
        ch = segment[i]
        if quote == "'":
            if ch == "'":
                quote = None
            else:
                buf.append(ch)
            i += 1
            continue
        if quote == '"':
            if ch == '"':
                quote = None
                i += 1
            elif ch == "\\" and i + 1 < n and segment[i + 1] in '"\\$`':
                buf.append(segment[i + 1])
                i += 2
            elif ch == "$":
                used, value = expand_at(i)
                buf.append(value)
                i += used
            else:
                buf.append(ch)
                i += 1
            continue
        # unquoted
        if ch.isspace():
            flush()
            i += 1
            continue
        in_word = True
        if ch in "'\"":
            quote = ch
            had_quote = True
            i += 1
        elif ch == "\\" and i + 1 < n:
            buf.append(segment[i + 1])
            i += 2
        elif ch == "$":
            used, value = expand_at(i)
            buf.append(value)
            i += used
        elif ch == "~" and not buf and home is not None and (i + 1 == n or segment[i + 1] in "/ \t"):
            buf.append(home)
            i += 1
        else:
            buf.append(ch)
            i += 1
    flush()
    return tokens


_REDIR_RE = re.compile(r"^(\d|&)?(>>?)(&\d)?(.*)$")


def parse_redirections(tokens: list[str]) -> tuple[list[str], str | None, bool, bool]:
    """Strip redirection tokens.

    Returns ``(clean_tokens, stdout_target, append, drop_stderr)`` where
    ``drop_stderr`` is True for ``2>/dev/null`` / ``&>file`` style redirects.
    """
    clean: list[str] = []
    target: str | None = None
    append = drop_stderr = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in (">", ">>", "1>", "1>>", "&>", ">&"):
            if i + 1 < len(tokens):
                target, append = tokens[i + 1], tok.endswith(">>")
            drop_stderr = drop_stderr or tok in ("&>", ">&")
            i += 2
            continue
        if tok in ("2>", "2>>"):
            drop_stderr = True
            i += 2
            continue
        if tok == "<":
            i += 2
            continue
        if tok == "&":
            i += 1
            continue
        m = _REDIR_RE.match(tok)
        if m and (m.group(1) or tok.startswith(">")):
            fd, op, dup, rest = m.groups()
            if fd == "2" and rest:  # 2>/dev/null, 2>err.log
                drop_stderr = True
            elif not dup and rest and fd in (None, "1", "&"):
                target, append = rest, op == ">>"
                drop_stderr = drop_stderr or fd == "&"
            i += 1
            continue
        clean.append(tok)
        i += 1
    return clean, target, append, drop_stderr


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "a": "\a", "0": "\0", "e": "\x1b"}


def _unescape(text: str) -> str:
    """Interpret echo -e / printf escapes (\\n, \\t, \\xHH, \\0NNN) without codecs surprises."""

    def repl(m: re.Match[str]) -> str:
        tok = m.group(1)
        if tok[0] == "x" and len(tok) > 1:
            return chr(int(tok[1:], 16))
        if tok[0] == "0" and len(tok) > 1:
            return chr(int(tok[1:], 8) & 0xFF)
        return _ESCAPES.get(tok, "\\" + tok)

    return re.sub(r"\\(x[0-9a-fA-F]{1,2}|0[0-7]{1,3}|.)", repl, text)


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _join(lines: list[str]) -> str:
    return "".join(line + "\n" for line in lines)


def _parse_count(args: list[str], default: int = 10) -> tuple[int, list[str]]:
    """Parse ``-n 5``, ``-n5``, ``-5`` for head/tail. Returns (n, remaining_args)."""
    n, rest, i = default, [], 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args):
            n = int(args[i + 1]) if args[i + 1].lstrip("-").isdigit() else default
            i += 2
            continue
        if a.startswith("-n") and a[2:].isdigit():
            n = int(a[2:])
        elif a.startswith("-") and a[1:].isdigit():
            n = int(a[1:])
        elif not a.startswith("-"):
            rest.append(a)
        i += 1
    return abs(n), rest


# --------------------------------------------------------------------------- #
# The shell                                                                    #
# --------------------------------------------------------------------------- #
class FakeShell:
    def __init__(self, username: str, hostname: str, client_ip: str):
        # The login name is attacker-controlled: keep it a valid Linux user name so it
        # can't inject paths ("../../etc") or terminal escapes into the prompt.
        safe = re.sub(r"[^a-z0-9_.-]", "", (username or "").lower())[:32].lstrip(".-")
        self.username = safe or "user"
        self.hostname = hostname
        self.client_ip = client_ip
        self.is_root = self.username == "root"
        self.home = "/root" if self.is_root else f"/home/{self.username}"
        self.fs = VirtualFS(hostname, self.username)
        if not self.fs.isdir(self.home):
            self.fs.nodes[self.home] = DIR
        self.cwd = self.home
        self.history: list[str] = []
        self.exit_requested = False
        self._depth = 0
        self._payloads: list[str] = []
        self._stderr: list[str] = []
        self.boot_time = datetime.now(timezone.utc) - timedelta(
            days=random.randint(12, 140), minutes=random.randint(0, 1440)
        )
        self.env = {
            "USER": self.username,
            "LOGNAME": self.username,
            "HOME": self.home,
            "SHELL": "/bin/bash",
            "PWD": self.cwd,
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOSTNAME": hostname,
        }

        def silent(_args: list[str], _stdin: str) -> str:
            return ""

        def const(text: str) -> Handler:
            return lambda _args, _stdin: text

        self._commands: dict[str, Handler] = {
            # navigation / files
            "pwd": self._pwd,
            "cd": self._cd,
            "ls": self._ls,
            "ll": lambda a, i: self._ls(["-l", *a], i),
            "dir": self._ls,
            "cat": self._cat,
            "touch": self._touch,
            "mkdir": self._mkdir,
            "rm": self._rm,
            "rmdir": self._rm,
            "cp": silent,
            "mv": silent,
            "chmod": silent,
            "chown": silent,
            "chattr": silent,
            "ln": silent,
            "find": silent,
            "stat": silent,
            "file": silent,
            # text processing (pipeline filters)
            "echo": self._echo,
            "printf": self._printf,
            "grep": self._grep,
            "egrep": self._grep,
            "wc": self._wc,
            "head": self._head,
            "tail": self._tail,
            "sort": self._sort,
            "uniq": self._uniq,
            "cut": self._cut,
            "awk": self._awk,
            "tr": self._tr,
            "base64": self._base64,
            "xargs": silent,
            "tee": self._tee,
            "sed": lambda a, i: i,
            # identity / system info
            "whoami": const(self.username + "\n"),
            "id": self._id,
            "hostname": const(hostname + "\n"),
            "uname": self._uname,
            "uptime": self._uptime,
            "w": self._w,
            "who": self._who,
            "ps": self._ps,
            "top": self._top,
            "free": self._free,
            "df": self._df,
            "nproc": const("4\n"),
            "lscpu": self._lscpu,
            "ifconfig": self._ifconfig,
            "ip": self._ip,
            "netstat": self._netstat,
            "ss": self._netstat,
            "last": self._last,
            "date": self._date,
            "mount": self._mount,
            "arch": const("x86_64\n"),
            "lspci": silent,
            "dmidecode": silent,
            "getconf": self._getconf,
            # shell builtins
            "history": self._history,
            "clear": const("\x1b[H\x1b[2J"),
            "exit": self._exit,
            "logout": self._exit,
            "quit": self._exit,
            "export": self._export,
            "env": self._env,
            "printenv": self._env,
            "set": self._env,
            "unset": silent,
            "which": self._which,
            "type": self._which,
            "true": silent,
            ":": silent,
            "false": silent,
            "sleep": silent,
            "cd..": lambda a, i: self._cd([".."], i),
            "enable": silent,
            "system": silent,
            # privilege / execution wrappers
            "sudo": self._sudo,
            "su": silent,
            "nohup": self._nohup,
            "timeout": self._timeout,
            "sh": self._sh,
            "bash": self._sh,
            "dash": self._sh,
            "busybox": self._busybox,
            "python": self._python,
            "python3": self._python,
            "perl": silent,
            # network
            "wget": self._wget,
            "curl": self._curl,
            "tftp": self._tftp,
            "ftpget": self._tftp,
            "ssh": const("ssh: connect to host port 22: Connection timed out\n"),
            "scp": silent,
            "nc": silent,
            "ping": self._ping,
            # admin
            "apt": self._apt,
            "apt-get": self._apt,
            "systemctl": silent,
            "service": silent,
            "crontab": self._crontab,
            "passwd": self._passwd,
            "useradd": silent,
            "adduser": silent,
            "usermod": silent,
            "chpasswd": silent,
            "iptables": silent,
            "ufw": silent,
            "kill": silent,
            "pkill": silent,
            "killall": silent,
            "tar": silent,
            "unzip": silent,
            "gzip": silent,
        }

    # ----------------------------------------------------------------- public
    @property
    def prompt(self) -> str:
        if self.cwd == self.home:
            shown = "~"
        elif self.cwd.startswith(self.home + "/"):
            shown = "~" + self.cwd[len(self.home) :]
        else:
            shown = self.cwd
        return f"{self.username}@{self.hostname}:{shown}{'#' if self.is_root else '$'} "

    def motd(self) -> str:
        now = datetime.now(timezone.utc)
        last_ip = f"10.0.{random.randint(0, 9)}.{random.randint(2, 250)}"
        return (
            "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/pro\n\n"
            f"  System information as of {now:%a %b %d %H:%M:%S UTC %Y}\n\n"
            "  System load:  0.08              Processes:             132\n"
            "  Usage of /:   37.4% of 77.35GB   Users logged in:       0\n"
            "  Memory usage: 18%               IPv4 address for eth0: 172.16.4.21\n\n"
            f"Last login: {(now - timedelta(hours=7)):%a %b %d %H:%M:%S %Y} from {last_ip}\n"
        )

    def run_line(self, line: str, record_history: bool = True) -> tuple[str, bool]:
        """Execute a full input line. Returns (output, all_commands_known)."""
        line = line.strip()
        if not line:
            return "", True
        if record_history:
            self.history.append(line)
        outputs: list[str] = []
        all_known = True
        for segment in split_command_line(line):
            out, known = self._run_segment(segment)
            outputs.append(out)
            all_known = all_known and known
            if self.exit_requested:
                break
        return "".join(outputs), all_known

    def take_payloads(self) -> list[str]:
        """Return (and clear) payloads decoded by ``base64 -d`` since the last call."""
        payloads, self._payloads = self._payloads, []
        return payloads

    # --------------------------------------------------------------- dispatch
    def _run_segment(self, segment: str) -> tuple[str, bool]:
        if self._depth >= MAX_DEPTH:  # caps `sudo sudo sh -c "sh -c ..."` chains
            return "", True
        self._depth += 1
        try:
            output, errors, known = "", [], True
            for stage in split_pipeline(segment):
                # stdout flows to the next stage; stderr goes straight to the terminal,
                # so `curl -s URL | sh` does not feed curl's error message into sh.
                output, err, stage_known = self._run_simple(stage, output)
                errors.append(err)
                known = known and stage_known
            return "".join(errors) + output, known
        finally:
            self._depth -= 1

    def _err(self, text: str) -> str:
        """Write to stderr from inside a command handler; returns '' for convenience."""
        self._stderr.append(text)
        return ""

    def _run_simple(self, stage: str, stdin: str) -> tuple[str, str, bool]:
        """Run one pipeline stage. Returns (stdout, stderr, known)."""
        tokens, redirect, append, drop_stderr = parse_redirections(tokenize(stage, self.env, self.home))
        # leading VAR=value assignments (already expanded by the tokenizer)
        while tokens and re.match(r"^[A-Za-z_]\w*=", tokens[0]):
            key, _, value = tokens.pop(0).partition("=")
            self.env[key] = value
        if not tokens:
            return "", "", True

        name, args = tokens[0], tokens[1:]
        base = posixpath.basename(name)

        if name.startswith("./") or (name.startswith("/") and base not in self._commands):
            path = self._resolve(name)
            if self.fs.isdir(path):
                return "", f"-bash: {name}: Is a directory\n", False
            if self.fs.exists(path):
                return "", f"-bash: {name}: Permission denied\n", False
            return "", f"-bash: {name}: No such file or directory\n", False

        handler = self._commands.get(base)
        if handler is None:
            return "", f"-bash: {base}: command not found\n", False

        saved, self._stderr = self._stderr, []
        try:
            output = handler(args, stdin)
        except Exception:  # an emulator bug must never kill the session
            output = ""
        err = "" if drop_stderr else "".join(self._stderr)
        self._stderr = saved

        if redirect:
            if not self.fs.write(self._resolve(redirect), output, append):
                return "", err + f"-bash: {redirect}: No such file or directory\n", True
            return "", err, True
        return output, err, True

    # ---------------------------------------------------------------- helpers
    def _resolve(self, path: str) -> str:
        if not path:
            return self.cwd
        joined = path if path.startswith("/") else posixpath.join(self.cwd, path)
        norm = posixpath.normpath(joined)
        return "/" + norm.lstrip("/") if norm not in ("", ".") else "/"

    def _read_inputs(self, files: list[str], stdin: str, cmd: str) -> tuple[str, str]:
        """Concatenate files (or stdin when none). Returns (content, errors)."""
        if not files:
            return stdin, ""
        content, errors = [], []
        for f in files:
            if f == "-":
                content.append(stdin)
                continue
            path = self._resolve(f)
            if path == "/etc/shadow" and not self.is_root:
                errors.append(f"{cmd}: {f}: Permission denied\n")
            elif self.fs.isdir(path):
                errors.append(f"{cmd}: {f}: Is a directory\n")
            elif self.fs.read(path) is None:
                errors.append(f"{cmd}: {f}: No such file or directory\n")
            else:
                content.append(self.fs.read(path) or "")
        return "".join(content), "".join(errors)

    # ------------------------------------------------------- file commands
    def _pwd(self, args, stdin):
        return self.cwd + "\n"

    def _cd(self, args, stdin):
        if args and args[0] == "-":
            return self.cwd + "\n"
        target = self._resolve(args[0] if args else self.home)
        if not self.fs.exists(target):
            return f"-bash: cd: {args[0]}: No such file or directory\n"
        if not self.fs.isdir(target):
            return f"-bash: cd: {args[0]}: Not a directory\n"
        if target.startswith("/root") and not self.is_root:
            return f"-bash: cd: {args[0]}: Permission denied\n"
        self.cwd = self.env["PWD"] = target
        return ""

    def _ls(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        paths = [a for a in args if not a.startswith("-")] or [self.cwd]
        long_fmt, show_all = "l" in flags, "a" in flags
        out: list[str] = []
        for p in paths:
            target = self._resolve(p)
            if not self.fs.exists(target):
                out.append(f"ls: cannot access '{p}': No such file or directory\n")
                continue
            is_dir = self.fs.isdir(target)
            names = self.fs.listdir(target) if is_dir else [posixpath.basename(target)]
            names = [".", "..", *names] if show_all else [n for n in names if not n.startswith(".")]
            if not long_fmt:
                if names:
                    out.append("  ".join(names) + "\n")
                continue
            out.append(f"total {len(names) * 4}\n")
            for n in names:
                full = posixpath.join(target, n) if is_dir else target
                node_dir = n in (".", "..") or self.fs.isdir(full)
                size = 4096 if node_dir else len(self.fs.read(full) or "")
                perm = "drwxr-xr-x" if node_dir else "-rw-r--r--"
                out.append(f"{perm} {2 if node_dir else 1} root root {size:>6} Mar 14 09:12 {n}\n")
        return "".join(out)

    def _cat(self, args, stdin):
        content, errors = self._read_inputs([a for a in args if not a.startswith("-") or a == "-"], stdin, "cat")
        return content + errors

    def _touch(self, args, stdin):
        for a in (x for x in args if not x.startswith("-")):
            p = self._resolve(a)
            if not self.fs.exists(p) and not self.fs.write(p, ""):
                return f"touch: cannot touch '{a}': No such file or directory\n"
        return ""

    def _mkdir(self, args, stdin):
        for a in (x for x in args if not x.startswith("-")):
            if not self.fs.mkdir(self._resolve(a)) and "-p" not in args:
                return f"mkdir: cannot create directory '{a}': File exists\n"
        return ""

    def _rm(self, args, stdin):
        for a in (x for x in args if not x.startswith("-")):
            p = self._resolve(a)
            if p not in ("/", self.home):  # keep the fake system usable
                self.fs.remove(p)
        return ""

    def _tee(self, args, stdin):
        append = "-a" in args
        for f in (a for a in args if not a.startswith("-")):
            self.fs.write(self._resolve(f), stdin, append)
        return stdin

    # ------------------------------------------------------- text filters
    def _echo(self, args, stdin):
        newline, interpret = True, False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            flag = args.pop(0)
            newline = newline and "n" not in flag
            interpret = interpret or "e" in flag
        text = " ".join(args)
        if interpret:
            text = _unescape(text)
        return text + ("\n" if newline else "")

    def _printf(self, args, stdin):
        if not args:
            return ""
        fmt = _unescape(args[0])
        values = iter(args[1:])
        return re.sub(r"%[sdi]", lambda _m: next(values, ""), fmt).replace("%%", "%")

    def _grep(self, args, stdin):
        flags, rest = "", []
        for a in args:
            if a.startswith("--") and not rest:
                continue  # long options such as --color=auto are ignored
            if a.startswith("-") and len(a) > 1 and not rest:
                flags += a[1:]
            else:
                rest.append(a)
        if not rest:
            return "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
        pattern, files = rest[0], rest[1:]
        content, errors = self._read_inputs(files, stdin, "grep")
        try:
            regex = re.compile(pattern, re.IGNORECASE if "i" in flags else 0)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE if "i" in flags else 0)
        matched = [ln for ln in _lines(content) if bool(regex.search(ln)) != ("v" in flags)]
        if "c" in flags:
            return f"{len(matched)}\n" + errors
        return _join(matched) + errors

    def _wc(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        files = [a for a in args if not a.startswith("-")]
        content, errors = self._read_inputs(files, stdin, "wc")
        counts = {"l": content.count("\n"), "w": len(content.split()), "c": len(content.encode())}
        selected = [k for k in "lwc" if k in flags] or ["l", "w", "c"]
        suffix = f" {files[0]}" if files else ""
        if len(selected) == 1:
            return f"{counts[selected[0]]}{suffix}\n" + errors
        return " ".join(f"{counts[k]:>7}" for k in selected) + suffix + "\n" + errors

    def _head(self, args, stdin):
        n, files = _parse_count(args)
        content, errors = self._read_inputs(files, stdin, "head")
        return _join(_lines(content)[:n]) + errors

    def _tail(self, args, stdin):
        n, files = _parse_count(args)
        content, errors = self._read_inputs(files, stdin, "tail")
        lines = _lines(content)
        return _join(lines[-n:] if n else []) + errors

    def _sort(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        content, _ = self._read_inputs([a for a in args if not a.startswith("-")], stdin, "sort")
        lines = _lines(content)
        if "u" in flags:
            lines = list(dict.fromkeys(lines))
        if "n" in flags:

            def key(s: str) -> float:
                m = re.match(r"\s*(-?\d+(?:\.\d+)?)", s)
                return float(m.group(1)) if m else 0.0

            lines.sort(key=key, reverse="r" in flags)
        else:
            lines.sort(reverse="r" in flags)
        return _join(lines)

    def _uniq(self, args, stdin):
        content, _ = self._read_inputs([a for a in args if not a.startswith("-")], stdin, "uniq")
        out: list[tuple[str, int]] = []
        for ln in _lines(content):
            if out and out[-1][0] == ln:
                out[-1] = (ln, out[-1][1] + 1)
            else:
                out.append((ln, 1))
        if "-c" in args:
            return "".join(f"{c:>7} {ln}\n" for ln, c in out)
        return _join([ln for ln, _ in out])

    def _cut(self, args, stdin):
        delim, fields, files, i = "\t", "", [], 0
        while i < len(args):
            a = args[i]
            if a == "-d" and i + 1 < len(args):
                delim, i = args[i + 1], i + 2
                continue
            if a.startswith("-d") and len(a) > 2:
                delim = a[2:]
            elif a == "-f" and i + 1 < len(args):
                fields, i = args[i + 1], i + 2
                continue
            elif a.startswith("-f"):
                fields = a[2:]
            elif not a.startswith("-"):
                files.append(a)
            i += 1
        content, errors = self._read_inputs(files, stdin, "cut")
        wanted: list[int] = []
        for part in fields.split(","):
            if part.isdigit():
                wanted.append(int(part))
            elif re.fullmatch(r"\d+-\d+", part):
                lo, hi = map(int, part.split("-"))
                wanted.extend(range(lo, min(hi, 64) + 1))
        if not wanted:
            return "cut: you must specify a list of bytes, characters, or fields\n"
        out = []
        for ln in _lines(content):
            cols = ln.split(delim[:1] or "\t")
            out.append((delim[:1] or "\t").join(cols[f - 1] for f in wanted if 0 < f <= len(cols)))
        return _join(out) + errors

    def _awk(self, args, stdin):
        sep, program, files, i = None, "", [], 0
        while i < len(args):
            a = args[i]
            if a == "-F" and i + 1 < len(args):
                sep, i = args[i + 1], i + 2
                continue
            if a.startswith("-F") and len(a) > 2:
                sep = a[2:]
            elif not program:
                program = a
            else:
                files.append(a)
            i += 1
        m = re.search(r"print\s+([^}]*)", program)
        if not m:
            return ""
        refs = re.findall(r"\$(\d+|NF)", m.group(1))
        content, errors = self._read_inputs(files, stdin, "awk")
        out = []
        for ln in _lines(content):
            cols = ln.split(sep) if sep else ln.split()
            vals = []
            for r in refs:
                if r == "NF":
                    vals.append(cols[-1] if cols else "")
                elif r == "0":
                    vals.append(ln)
                elif int(r) <= len(cols):
                    vals.append(cols[int(r) - 1])
                else:
                    vals.append("")
            out.append(" ".join(vals))
        return _join(out) + errors

    def _tr(self, args, stdin):
        sets = [a for a in args if not a.startswith("-")]
        if "-d" in args and sets:
            return "".join(ch for ch in stdin if ch not in sets[0])
        if len(sets) >= 2 and len(sets[0]) == len(sets[1]):
            return stdin.translate(str.maketrans(sets[0], sets[1]))
        return stdin

    def _base64(self, args, stdin):
        files = [a for a in args if not a.startswith("-")]
        content, errors = self._read_inputs(files, stdin, "base64")
        if "-d" in args or "--decode" in args:
            try:
                decoded = base64.b64decode("".join(content.split()), validate=False).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                return "base64: invalid input\n"
            if decoded.strip():
                self._payloads.append(decoded[:MAX_PAYLOAD])
            return decoded
        return base64.b64encode(content.encode()).decode() + "\n" + errors

    # ------------------------------------------------------- system info
    def _id(self, args, stdin):
        if self.is_root:
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        u = self.username
        return f"uid=1000({u}) gid=1000({u}) groups=1000({u}),4(adm),27(sudo)\n"

    def _uname(self, args, stdin):
        flags = "".join(a.lstrip("-") for a in args)
        if "a" in flags:
            return (
                f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP "
                "Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
            )
        parts = []
        if not flags or "s" in flags:
            parts.append("Linux")
        if "n" in flags:
            parts.append(self.hostname)
        if "r" in flags:
            parts.append("5.15.0-105-generic")
        if "v" in flags:
            parts.append("#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024")
        if any(f in flags for f in "mpi"):
            parts.append("x86_64")
        if "o" in flags:
            parts.append("GNU/Linux")
        return " ".join(parts) + "\n"

    def _uptime(self, args, stdin):
        now = datetime.now(timezone.utc)
        up = now - self.boot_time
        return (
            f" {now:%H:%M:%S} up {up.days} days, {up.seconds // 3600}:{(up.seconds // 60) % 60:02d},"
            "  1 user,  load average: 0.08, 0.03, 0.01\n"
        )

    def _w(self, args, stdin):
        now = datetime.now(timezone.utc)
        return self._uptime(args, stdin) + (
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{self.username:<8} pts/0    {self.client_ip:<16} {now:%H:%M}    0.00s  0.02s  0.00s w\n"
        )

    def _who(self, args, stdin):
        return f"{self.username:<8} pts/0        {datetime.now(timezone.utc):%Y-%m-%d %H:%M} ({self.client_ip})\n"

    def _ps(self, args, stdin):
        if any(a in ("aux", "-aux", "-ef", "-e", "ax") for a in args):
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 167744 11420 ?        Ss   Oct03   0:04 /sbin/init\n"
                "root         612  0.0  0.0  15432  9012 ?        Ss   Oct03   0:00 sshd: /usr/sbin/sshd -D\n"
                "mysql        744  0.1  4.8 1795544 392120 ?      Ssl  Oct03  12:41 /usr/sbin/mysqld\n"
                "www-data     801  0.0  0.1  55284  6120 ?        S    Oct03   0:03 nginx: worker process\n"
                f"{self.username:<8}    2231  0.0  0.0   8964  5440 pts/0    Ss   10:02   0:00 -bash\n"
            )
        return "    PID TTY          TIME CMD\n   2231 pts/0    00:00:00 bash\n   2290 pts/0    00:00:00 ps\n"

    def _top(self, args, stdin):
        return (
            "top - "
            + datetime.now(timezone.utc).strftime("%H:%M:%S")
            + " up 41 days,  1 user,  load average: 0.08, 0.03, 0.01\n"
            "Tasks: 132 total,   1 running, 131 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.2 us,  0.4 sy,  0.0 ni, 98.3 id,  0.1 wa\n"
            "MiB Mem :   7957.2 total,   5108.4 free,   1254.0 used,   1594.7 buff/cache\n"
        )

    def _free(self, args, stdin):
        head = "               total        used        free      shared  buff/cache   available\n"
        if "-h" in args:
            return head + (
                "Mem:           7.8Gi       1.2Gi       5.0Gi        12Mi       1.6Gi       6.6Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi\n"
            )
        if "-m" in args:
            return head + (
                "Mem:            7957        1254        5108          12        1594        6750\n"
                "Swap:           2047           0        2047\n"
            )
        if "-g" in args:
            return head + "Mem:               7           1           4           0           1           6\n"
        return head + (
            "Mem:         8148132     1284112     5231048       12592     1632972     6912340\n"
            "Swap:        2097148           0     2097148\n"
        )

    def _df(self, args, stdin):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        78G   29G   45G  40% /\n"
            "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
            "/dev/sda15      105M  6.1M   99M   6% /boot/efi\n"
        )

    def _lscpu(self, args, stdin):
        return (
            "Architecture:            x86_64\n"
            "CPU op-mode(s):          32-bit, 64-bit\n"
            "CPU(s):                  4\n"
            "Vendor ID:               GenuineIntel\n"
            "Model name:              Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
            "Thread(s) per core:      1\n"
            "Core(s) per socket:      4\n"
        )

    def _getconf(self, args, stdin):
        return "4\n" if args and args[0] in ("_NPROCESSORS_ONLN", "_NPROCESSORS_CONF") else ""

    def _ifconfig(self, args, stdin):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 172.16.4.21  netmask 255.255.255.0  broadcast 172.16.4.255\n"
            "        ether 52:54:00:3a:91:7c  txqueuelen 1000  (Ethernet)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
        )

    def _ip(self, args, stdin):
        if args and args[0] in ("r", "route"):
            return "default via 172.16.4.1 dev eth0 proto dhcp src 172.16.4.21 metric 100\n"
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
            "    inet 172.16.4.21/24 brd 172.16.4.255 scope global eth0\n"
        )

    def _netstat(self, args, stdin):
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        )

    def _last(self, args, stdin):
        return (
            "ubuntu   pts/0        10.0.3.17        Mon Nov  3 08:14 - 09:02  (00:48)\n"
            "reboot   system boot  5.15.0-105-gener Fri Oct  3 22:10   still running\n\n"
            "wtmp begins Fri Oct  3 22:10:41 2025\n"
        )

    def _date(self, args, stdin):
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"

    def _mount(self, args, stdin):
        return "/dev/sda1 on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"

    # ------------------------------------------------------- builtins
    def _history(self, args, stdin):
        if "-c" in args:
            self.history.clear()
            return ""
        return "".join(f"  {i + 1:>3}  {c}\n" for i, c in enumerate(self.history))

    def _exit(self, args, stdin):
        self.exit_requested = True
        return "logout\n"

    def _export(self, args, stdin):
        for a in args:
            if "=" in a:
                k, _, v = a.partition("=")
                self.env[k] = v
        return ""

    def _env(self, args, stdin):
        return "".join(f"{k}={v}\n" for k, v in self.env.items())

    def _which(self, args, stdin):
        return "".join(f"/usr/bin/{a}\n" for a in args if a in self._commands)

    # ------------------------------------------------------- wrappers
    def _run_args(self, args: list[str]) -> str:
        return self._run_segment(shlex.join(args))[0] if args else ""

    def _sudo(self, args, stdin):
        while args and args[0].startswith("-"):
            args = args[1:]
        return self._run_args(args)

    def _nohup(self, args, stdin):
        return self._run_args(args) if args else "nohup: missing operand\n"

    def _timeout(self, args, stdin):
        return self._run_args(args[1:])

    def _sh(self, args, stdin):
        if len(args) >= 2 and args[0] == "-c":
            return self.run_line(args[1], record_history=False)[0]
        if not args and stdin.strip():  # `echo cmd | sh`, `base64 -d | bash`
            return self.run_line(stdin[:MAX_PAYLOAD], record_history=False)[0]
        return ""

    def _busybox(self, args, stdin):
        # Mirai-family bots probe with `/bin/busybox RANDOMTAG` and expect this exact reply.
        if not args:
            return "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n"
        if args[0] in self._commands and args[0] != "busybox":
            return self._run_args(args)
        return f"{args[0]}: applet not found\n"

    def _python(self, args, stdin):
        if args and args[0] in ("-V", "--version"):
            return "Python 3.10.12\n"
        return ""

    # ------------------------------------------------------- network (all fake)
    @staticmethod
    def _host_of(url: str) -> str:
        return url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]

    @staticmethod
    def _urls(args: list[str]) -> list[str]:
        return [a for a in args if "://" in a or (not a.startswith("-") and re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", a))]

    # Like the real tools, all diagnostics go to stderr, so `curl -s URL | sh`
    # pipes nothing into sh and `wget ... 2>/dev/null` prints nothing.
    def _wget(self, args, stdin):
        urls = self._urls(args)
        if not urls:
            return self._err(
                "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n"
            )
        quiet = any(a in ("-q", "--quiet") or (a.startswith("-") and not a.startswith("--") and "q" in a) for a in args)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        for u in urls:
            host = self._host_of(u)
            if not quiet:
                self._err(
                    f"--{ts}--  {u}\nResolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                )
            self._err(f"wget: unable to resolve host address '{host}'\n")
        return ""

    def _curl(self, args, stdin):
        urls = self._urls(args)
        if not urls:
            return self._err("curl: try 'curl --help' or 'curl --manual' for more information\n")
        silent = any(
            a in ("-s", "--silent") or (a.startswith("-") and not a.startswith("--") and "s" in a) for a in args
        )
        show_error = any(
            a in ("-S", "--show-error") or (a.startswith("-") and not a.startswith("--") and "S" in a) for a in args
        )
        if not silent or show_error:
            self._err(f"curl: (6) Could not resolve host: {self._host_of(urls[0])}\n")
        return ""

    def _tftp(self, args, stdin):
        return self._err("tftp: timeout\n")

    def _ping(self, args, stdin):
        hosts = [a for a in args if not a.startswith("-")]
        return self._err(f"ping: {hosts[-1]}: Temporary failure in name resolution\n") if hosts else ""

    # ------------------------------------------------------- admin
    def _apt(self, args, stdin):
        if args and args[0] in ("install", "update", "upgrade", "remove"):
            return (
                "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1873 (unattended-upgr)\n"
                "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), "
                "is another process using it?\n"
            )
        return ""

    def _crontab(self, args, stdin):
        return f"no crontab for {self.username}\n" if "-l" in args else ""

    def _passwd(self, args, stdin):
        return "passwd: Authentication token manipulation error\npasswd: password unchanged\n"
