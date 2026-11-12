## What does this change?

<!-- One or two sentences. Link the issue: Closes #123 -->

## Type

- [ ] Bug fix
- [ ] New emulated command / detection rule
- [ ] Dashboard
- [ ] Docs / CI

## Checklist

- [ ] `ruff check .` passes
- [ ] `pytest` passes and new behaviour has a test
- [ ] No real command execution, file I/O or network access added to the fake shell
- [ ] Attacker-controlled strings are still escaped / bound as SQL parameters
- [ ] CHANGELOG.md updated under *Unreleased*
