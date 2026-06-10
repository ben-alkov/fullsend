# Testing workflow changes

This guide explains how to test changes to Fullsend's GitHub Actions workflows.

## Vendored installs (recommended for PR testing)

Install or re-install with `--vendor` to copy reusable workflows, actions, agent
definitions, and the CLI binary from your local checkout into the config repo or
`.fullsend/` directory:

```bash
fullsend admin install "$ORG" \
  --vendor \
  --fullsend-source "$PWD" \
  --skip-app-setup \
  --skip-mint-check \
  --mint-url "$MINT_URL" \
  # ... other flags
```

E2e uses `--vendor` so CI exercises the commit under test, not upstream `@v0`.
After changing reusable workflows or agent content, re-run install (or
`fullsend github setup`) with `--vendor` to refresh vendored files.
`fullsend github sync-scaffold` updates thin caller templates and auto-detects
vendored vs layered mode from `.defaults/action.yml` presence.

Runtime skips the upstream sparse checkout when `.defaults/action.yml` is
present (vendored install) and stages content from `.defaults/` instead.

## Layered installs: pin upstream ref

In layered mode (default), thin callers reference upstream reusable workflows at
`fullsend-ai/fullsend@v0`. To test a specific upstream ref without vendoring,
change the `uses:` ref in the thin caller workflows.

### Per-repo mode

In your repository modify the dispatch job at `.github/workflows/fullsend.yaml`:

```yaml
# .github/workflows/fullsend.yaml
jobs:
  dispatch:
    uses: fullsend-ai/fullsend/.github/workflows/reusable-dispatch.yml@<YOUR_VERSION>
```

### Per-org mode

**WARNING**: this impacts all repositories, so proceed with care. You can install
your test repository using per-repo mode to avoid this problem.

In your `.fullsend` repository modify the desired stage workflow file:

```yaml
# .github/workflows/triage.yml
jobs:
  triage:
    uses: fullsend-ai/fullsend/.github/workflows/reusable-triage.yml@<YOUR_VERSION>
```

Then push and trigger a Fullsend action. When the ref is deleted from
fullsend-ai/fullsend, revert to your desired reference.

See [ADR 0046](../../ADRs/0046-vendored-installs-with-vendor-flag.md) for the
full distribution model.
