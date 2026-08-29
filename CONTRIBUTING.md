# Contributing

Two-person team workflow. Keep `main` green; do all work on branches via PRs.

## One-time setup (do this on your own machine)

```bash
git clone https://github.com/adivishall/sentinel.git
cd sentinel
git config user.name  "Your Name"
git config user.email "your-github-email@example.com"   # the email on YOUR GitHub account
pip install -r requirements-dev.txt
```

Using the email tied to *your* GitHub account is what makes your commits show up
under *your* profile. This matters — it's how we each show what we built.

## The loop

```bash
git checkout main && git pull                 # start fresh
git checkout -b feat/<short-name>             # your own branch
# ... make changes ...
make lint                                     # ruff + black + mypy must pass
make test                                     # 26+ tests must pass
git commit -m "type: what changed"            # small, meaningful commits
git push -u origin feat/<short-name>
gh pr create --base main                      # open a PR; the other reviews + merges
```

CI (GitHub Actions) runs lint + type-check + tests on every push and PR. A red
check blocks the merge.

## Commit message style

`type: summary` — types: `feat`, `fix`, `test`, `docs`, `chore`, `ci`.
Examples: `feat(kyb): structured adjudicator for onboarding`, `test: homoglyph cases`.

## Ground rules

- Never commit secrets. `ANTHROPIC_API_KEY` goes in `.env` (git-ignored).
- Tests must pass offline (no API key): `SENTINEL_FORCE_OFFLINE=1`.
- The firewall's decision must stay fact-based — never let untrusted prose reach L3.

## Open tasks

See the [issues](https://github.com/adivishall/sentinel/issues).
