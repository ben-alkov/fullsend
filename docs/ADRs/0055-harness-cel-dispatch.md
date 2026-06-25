---
title: "55. Harness CEL triggers and fullsend dispatch drivers"
status: Accepted
relates_to:
  - agent-architecture
  - agent-infrastructure
topics:
  - dispatch
  - harness
  - cel
  - forge
---

# 55. Harness CEL triggers and fullsend dispatch drivers

Date: 2026-06-23

## Status

Accepted

## Context

Custom agents should be easy to author and portable across forges. Today, adding
one means editing shared dispatch bash in GitHub Actions, adding per-stage
workflow files, and re-implementing routing per install mode — work that is
GitHub-specific and not co-located with the harness
([gitlab-implementation.md](../problems/gitlab-implementation.md#event-mapping),
[ADR 0045](0045-forge-portable-harness-schema.md),
[ADR 0026](0026-stage-based-dispatch-for-agent-workflow-decoupling.md)).

A second constraint is **security allow-listing**: token mint and inference APIs
trust only explicit `job_workflow_ref` values
([ADR 0029](0029-central-token-mint-secretless-fullsend.md)). Each new agent
workflow file requires operational updates in both surfaces, which discourages
org-specific agents.

Colocating CEL `trigger` rules on harness files and routing through
**`fullsend dispatch`** lets orgs drop in harness YAML without new allow-listed
workflows. Routing nuance (slash commands, labels, actor ACLs, fork gates) lives
in portable expressions over a forge-neutral **`NormalizedEvent`**
([normative v1 spec](../normative/normalized-event/v1/)).

## Options

### Option A: Keep routing in workflow bash (status quo)

- Proven behavior; remains forge-coupled and hard to test.

### Option B: Central `config.yaml` routing table

- One audit file; rules drift from harness definitions.

### Option C: CEL `trigger` on harness files

- Self-describing agents; requires `fullsend dispatch` and input/output drivers.

## Decision

Adopt **Option C**.

- **`NormalizedEvent`:** forge-neutral routing input
  ([`docs/normative/normalized-event/v1/`](../normative/normalized-event/v1/),
  [ADR 0015](0015-normative-specifications-directory.md)). Examples and
  projection rules live in the normative tree — not duplicated here.
- **Harness `trigger`:** optional CEL boolean with root variable `event`. No
  `trigger` → manual `fullsend run` only. Multiple harnesses may match (parallel
  fan-out).
- **`fullsend dispatch`:** input driver → evaluate harness CEL → project
  execution ref (unchanged `fullsend run` contract) → output driver
  (`gha-matrix`, `json`, etc.). Drivers are flagged or auto-detected
  (`GITHUB_EVENT_PATH` → `gha-event`).
- **Workflow integration:** replace bash stage routing with
  `fullsend dispatch --output-driver gha-matrix` and a dynamic job matrix.
  Deprecate `# fullsend-stage:` markers and static per-stage `workflow_call`
  jobs.

## Consequences

- Custom agents ship as harness files with `trigger`; no per-agent workflow or
  dispatch bash edits.
- Mint and inference allow-lists can trust a small set of generic runner
  workflows instead of every agent-specific workflow file.
- Routing is unit-testable via `NormalizedEvent` fixtures without GitHub
  Actions; only input drivers are forge-specific.
- `# fullsend-stage:` markers and duplicated bash routers are removed during
  implementation.
- CEL linting, documentation, and eval fixtures are required
  ([testing-agents.md](../problems/testing-agents.md)); sequential multi-agent
  chaining remains out of scope ([ADR 0018](0018-scripted-pipeline-for-multi-agent-orchestration.md)).
