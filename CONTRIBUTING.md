# Contributing

Thanks for your interest! Bug reports, new emulated commands and detection rules are all welcome.

## Development setup

```bash
git clone https://github.com/Youssef840/ssh-honeypot.git
cd ssh-honeypot
python -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install               # optional: lint on every commit
```

## Before opening a pull request

```bash
ruff format .
ruff check .
pytest --cov
```

All must pass — CI runs them on Linux and Windows for Python 3.10–3.13.

## Ground rules

1. **The fake shell must never touch the real system.** No `subprocess`, `os.system`, real file
   writes or network calls in `honeypot/fake_shell.py`. PRs that add any will be closed.
2. **Treat every attacker string as hostile** — bound SQL parameters only, never `|safe` in
   templates, never `innerHTML` in JavaScript.
3. Add a test for every new command, detection rule or bug fix.
4. Keep commits focused and use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`).

## Adding an emulated command

1. Write a method `_name(self, args, stdin) -> str` in `FakeShell`.
2. Register it in `self._commands`.
3. Add a test in `tests/test_fake_shell.py`.

## Adding a detection rule

Append a `(regex, points, tag, mitre_technique)` tuple to `RULES` in `honeypot/analysis.py`
and cover it in `tests/test_analysis.py`.
