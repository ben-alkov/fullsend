---
title: "56. Per-repo pre-commit tools registry"
status: Accepted
relates_to:
  - agent-infrastructure
  - security-threat-model
topics:
  - tool-dependencies
  - additive-merge
  - supply-chain-security
---

# 56. Per-repo pre-commit tools registry

Date: 2026-06-25

## Status

Accepted

Extends [PR #1055](https://github.com/fullsend-ai/fullsend/pull/1055).
Related: [#1270](https://github.com/fullsend-ai/fullsend/issues/1270)

## Context

PR #1055 introduced `.pre-commit-tools.yaml` — a registry mapping
pre-commit hooks to the system tools they require. The registry can be
fully replaced at the org level via `customized/scripts/` (L1 override,
ADR 0035), but repos needing one extra tool must copy the entire file.

## Decision

Add L2 additive merge: the resolver discovers a per-repo
`.pre-commit-tools.yaml` at the target repo root and merges it with
upstream/org defaults. New entries extend, matching `(repo, hook_id)`
entries override, and `exclude: true` suppresses.

### Resolution order

```
upstream defaults → org L1 (full replacement) → per-repo L2 (additive merge)
```

### Security

The per-repo registry is untrusted input that feeds the tool installer
running outside the sandbox. Caller scripts read it from the **base
branch** only (`git show origin/${TARGET_BRANCH}:...`), not the working
tree. PR-contributed registries don't take effect until merged.

### Interface

The resolver accepts `--local-registry <path>`. Caller scripts extract
the base-branch file to a temp file and pass it via this flag.
Malformed input emits warnings and falls back to upstream unchanged.

## Consequences

- Repos extend the registry without duplicating it.
- L1 full-replacement remains available for orgs needing complete control.
- New per-repo registries take effect only after merge to the base
  branch (deliberate security trade-off).
- Two per-repo paths exist: `.fullsend/customized/scripts/` (L1 full
  replacement) vs `.pre-commit-tools.yaml` at root (L2 additive).
