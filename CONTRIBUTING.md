# Contributing to Bernetes-Buster

Thanks for your interest. This project is public and AGPL-licensed, but `main` is protected so the public cannot merge changes without maintainer approval.

## Rules

1. **Do not push to `main`.** Open a pull request from a fork or feature branch.
2. PRs need **at least one approving review from a code owner** (`@Maximebb`).
3. **CI must pass** (`Build, unit tests, smoke test`).
4. Review threads must be **resolved** before merge.
5. Keep changes focused; include/update smoke tests when adding checks.

## Local checks

```bash
bash test/smoke.sh
docker build -t bernetes-buster:local .
```

## License of contributions

By contributing, you agree your contributions are licensed under the **GNU Affero General Public License v3.0 or later**, the same license as the project.
