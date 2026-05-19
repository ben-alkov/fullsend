# AGENTS.md

See [CLAUDE.md](CLAUDE.md) for project rules and design decisions.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format for every commit. The allowed types are: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`, `perf`. See [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages) for the full specification.

This is not optional — GoReleaser parses commit prefixes to build release notes. A missing or wrong prefix produces incorrect changelogs.

When reviewing PRs, check that commit messages and PR titles follow this format. Flag violations as a required change — they are not cosmetic.
