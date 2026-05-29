---
name: cutting-releases
description: >
  Use when the user wants to tag a release, cut a release candidate, or ship a
  new version. Also use when asking about release process, versioning, or how
  GoReleaser is configured.
allowed-tools: Read, Grep, Glob, AskUserQuestion, Bash(git tag:*), Bash(git log:*), Bash(git diff:*), Bash(git pull:*), Bash(git push:*), Bash(gh release:*), Bash(gh run:*), Bash(git checkout:*), Bash(git fetch:*), Bash(bash skills/cutting-releases/scripts/install-binary.sh:*)
---

# Cutting Releases

Releases are driven by annotated git tags. When a tag matching `v*` is pushed,
the `.github/workflows/release.yml` workflow runs GoReleaser, which builds
binaries, generates a changelog, and creates the GitHub release. The release
title comes from the tag annotation via `name_template` in `.goreleaser.yml`.

## Pre-Flight Release Check

Run this audit **before** tagging. The goal is to verify that moving
the `v0` reusable-workflow tag will not break downstream consumers,
and to identify what needs post-flight verification.

Start by fetching the latest remote state:

```
git fetch origin
```

### A. Audit reusable workflow changes

```
git diff v0..origin/main -- .github/workflows/reusable-*.yml
```

For each changed workflow, read the full diff and check:

- **Inputs:** Were any inputs removed or renamed? Were required inputs
  added without defaults? These are breaking — callers will fail.
- **Outputs:** Were any job outputs removed or renamed? Callers that
  reference them will break.
- **Secrets:** Were new secrets added to `secrets:` blocks? Callers
  must already have those secrets or the workflow will fail silently.
- **Environment variables:** New env vars passed to steps are additive
  and safe. Changed env var names used in conditionals may alter
  behavior.
- **Job/step IDs:** Renamed job IDs break `needs:` references in
  caller workflows.
- **Permissions:** Changes to `permissions:` blocks may fail if the
  calling workflow's token doesn't grant the new scopes.

Classify each change as:
- **Additive** (new optional inputs, new env vars) — safe.
- **Default change** (different default values) — note for migration.
- **Breaking** (removed/renamed inputs, outputs, jobs, new required
  secrets) — block the release until resolved.

### B. Audit scaffold and template changes

```
git diff v0..origin/main -- internal/scaffold/fullsend-repo/
```

Scaffold files are deployed at `github setup` time, not consumed live
via `@v0`. Changes here affect **new installs and re-scaffolds only**.
Review for:

- **Agent definitions** (`agents/`): Changed models, tools, or
  instructions alter agent behavior on next scaffold.
- **Harness configs** (`harness/`): Changed resource limits, allowed
  tools, or validation rules.
- **Hook scripts** (`scripts/`): Changed pre/post hooks run inside
  agent sandboxes.
- **Skill files** (`skills/`): New or changed agent skills.
- **Workflow templates** (`.github/workflows/`): Templates that get
  copied into target repos at scaffold time.

These do not require post-flight verification against running systems,
but note significant behavior changes for the release summary.

### C. Audit CLI and function changes

```
git log --oneline v0..origin/main -- cmd/ internal/
```

For commits touching `cmd/` or `internal/cli/`, read the diffs and
check:

- **Renamed flags or sub-commands:** Deprecated aliases must be
  preserved via `MarkDeprecated` + `MarkHidden`. If a flag was
  removed without an alias, this is breaking.
- **Changed defaults:** Pool names, regions, WIF provider names, or
  project ID defaults that differ from the previous release require
  a migration note in the release summary.
- **New sub-commands or flags:** Additive, safe. Note for changelog.
- **Behavioral changes in `internal/`:** Read the changed functions
  to understand if existing workflows (mint enroll/unenroll, inference
  provision, app setup) behave differently. Check backward compat by
  verifying the old invocation still works.

### D. Check CI on main

```
gh run list --branch=main --limit=5
```

All recent runs should be passing. If E2E tests are failing, investigate
before releasing.

### E. Identify post-flight check areas

Based on the changes found in steps A–C, determine what needs
post-flight verification after the `v0` tag moves:

- **Reusable workflow changes** → verify workflow runs in fullsend-ai
  repos resolve `@v0` correctly and pass.
- **New secrets or permissions** → verify affected workflows don't
  fail on missing secrets.
- **CLI default changes** → note migration steps for existing
  installs in the release summary.
- **No reusable workflow changes** → post-flight can be limited to
  confirming the release artifacts built correctly.

### F. Present summary

Summarize findings to the user in a table:

| Area | Changes | Breaking? |
|------|---------|-----------|
| Reusable workflows | ... | No/Yes |
| Scaffold templates | ... | No/Yes |
| CLI / internal | ... | No/Yes |

List the post-flight check areas identified in step E.

Give a **GO / NO-GO** verdict. Do not proceed until the user confirms.

---

## Process

Follow these steps in order.

### 1. Confirm the branch

Releases should be cut from `main`. Verify you are on `main` and up to date:

```
git checkout main && git pull
```

### 2. Determine the version

Check the latest tag:

```
git tag --sort=-v:refname | head -5
```

Decide the next version following semver:

| Change type | Example bump |
|---|---|
| Breaking / major milestone | `v1.0.0` |
| New functionality (MVP, feature set) | `v0.X.0` |
| Bug fixes only | `v0.0.X` |
| Release candidate | `v0.X.0-rc.N` |

### 3. Confirm the version with the user

Use `AskUserQuestion` to present your proposed version tag and the rationale
for your choice. For example:

> I'd suggest `v0.2.0` — there are 5 new `feat:` commits since `v0.1.0` and
> no breaking changes. Does that look right, or would you prefer a different
> version?

Do not proceed until the user confirms.

### 4. Ask for a tag subject

Use `AskUserQuestion` to ask:

> Any special title for this release? (e.g. "MVP Release Candidate 1")
> Leave blank to use just the version tag.

The answer becomes the tag subject line. If blank, do **not** use the version
as the subject — leave the subject empty so that GoReleaser's `name_template`
renders just the tag without duplication.

### 5. Gather changes since last tag

```
git log --oneline <previous-tag>..HEAD
```

Summarize the changes into categories (features, fixes, refactors). Exclude
commits that start with `docs:`, `test:`, `chore:`, `ci:`, or `build:` — GoReleaser filters
these from the changelog anyway.

### 6. Create the annotated tag

Build the tag message:

- **Line 1 (subject):** The custom title from step 4, if one was given.
  If no custom title, **omit the subject line** — start the annotation
  body directly with the highlights. This avoids duplicating the version
  in the release title.
- **Lines 3+:** Summary of highlights organized by category.

```
git tag -a v0.X.0 -m "<message>"
```

The first line of the annotation flows into the GitHub release title via
GoReleaser's `name_template: "{{ .Tag }}{{ if and .TagSubject (ne .TagSubject .Tag) }}: {{ .TagSubject }}{{ end }}"`.

### 7. Push the tag

```
git push origin <tag>
```

GoReleaser takes over from here. Verify the workflow starts:

```
gh run list --workflow=release.yml --limit=1
```

### 8. Move the `v0` tag

Downstream orgs reference reusable workflows via `@v0`. After the
version tag is pushed, move `v0` to the same commit:

```
git tag -f v0 <tag>
git push origin v0 --force
```

This updates all `@v0` workflow references immediately. The Sandbox
Images workflow (triggered by tag push) will also run.

### 9. Run post-flight verification

Proceed to the **Post-Flight Verification** section below. This
waits for CI workflows, verifies release artifacts, and checks
downstream `@v0` resolution.

### 10. Install the binary locally

Ask the user where to install (default: `~/.local/bin/`), then run
the install script using its repo-root-relative path:

```bash
bash skills/cutting-releases/scripts/install-binary.sh <tag> [install-dir]
```

The script downloads the release archive, verifies its SHA-256 checksum
against the release's `checksums.txt`, and installs the binary as
`fullsend-<tag>` so multiple versions can coexist.

## Post-Flight Verification

Run after the version tag is pushed, the `v0` tag is moved, and the
CI workflows complete. Focus on the areas identified during pre-flight
step E.

### A. Wait for CI workflows

Wait for the Release workflow (triggered by the `v*` tag) and the
Sandbox Images workflow (triggered by the `v0` tag move) to complete:

```
gh run list --workflow=release.yml --limit=1
gh run list --workflow=sandbox-images.yml --limit=1
```

Both must pass before proceeding. If either fails, investigate and
resolve before continuing — a broken release or sandbox image affects
all downstream consumers.

### B. Verify the release artifacts

```
gh release view <tag>
```

Check that the title, changelog, and binary assets look correct.
Verify the release is not marked as a draft.

### C. Check fullsend-ai repos

The skill user is a fullsend repo admin, so fullsend-ai org repos
are always accessible. Check recent workflow runs in the org's repos
that consume `@v0` reusable workflows:

```
gh run list --repo fullsend-ai/fullsend --limit=3
gh run list --repo fullsend-ai/.fullsend --limit=3
```

Look for runs that started **after** the `v0` tag move. Confirm they
completed without workflow-resolution errors (e.g. "could not find
reusable workflow"). If no runs occurred naturally, check for any
recent failed or cancelled runs that can be retriggered:

```
gh run list --repo fullsend-ai/.fullsend --status=failure --limit=3
```

Present any candidate to the user for confirmation before retriggering:

> I found run `<run-id>` (failed) in `fullsend-ai/.fullsend`.
> Retrigger it to verify `@v0` resolves?

Once confirmed:

```
gh run rerun <run-id> --failed --repo fullsend-ai/.fullsend
```

### D. Check additional downstream repos (optional)

Use `AskUserQuestion` to ask if the user has access to additional
downstream orgs:

> Do you have access to any other downstream orgs/repos to verify?
> (e.g. "konflux-ci, redhat-developer/rhdh-agentic")
> Leave blank to skip.

If the user provides repos, repeat the same checks from step C for
each one. If blank, skip this step — not all admins have access to
every enrolled org.

### E. Present post-flight summary

Summarize results to the user:

| Org/Repo | `@v0` Refs | Status |
|----------|-----------|--------|
| fullsend-ai/.fullsend | Confirmed | Passing |
| ... | ... | ... |

Distinguish between:
- **Release-related failures** — workflow resolution errors, missing
  secrets, or permission failures caused by the tag move.
- **Unrelated failures** — agent runtime errors, external API issues,
  or pre-existing test failures.

---

## Notes

- **Pre-releases:** Tags with `-rc.N`, `-alpha.N`, or `-beta.N` suffixes are
  automatically marked as pre-releases by GoReleaser.
- **Never delete a published tag.** If a release is bad, cut a new patch or RC.
- **The changelog** is auto-generated from commit messages. Conventional commit
  prefixes (`feat:`, `fix:`, etc.) produce clean changelogs.
- **The `v0` tag** is a moving tag consumed by downstream orgs for reusable
  workflows. Always move it as part of the release process (step 8).
