# NormalizedEvent v1

Forge-neutral routing input for `fullsend dispatch` and harness CEL `trigger`
expressions ([ADR 0055](../../../ADRs/0055-harness-cel-dispatch.md)).

## Contract

- **Schema:** [`normalized-event.schema.json`](normalized-event.schema.json)
- **CEL context:** harness `trigger` expressions receive a single root variable
  `event` bound to a `NormalizedEvent` object.
- **Versioning:** breaking changes require `docs/normative/normalized-event/v2/`.
- **Authorization:** `fullsend dispatch` enforces
  [ADR 0054](../../../ADRs/0054-require-authorization-on-all-agent-dispatch-paths.md)
  as a platform-level gate after normalization and **before** CEL evaluation.
  Harness `trigger` expressions express routing only, not permission policy.

## Adapters

Input drivers map native forge events into this struct:

| Driver | Source |
|--------|--------|
| `gha-event` | `GITHUB_EVENT_PATH` + `gh` snapshot for labels and change-proposal metadata |
| `json` | stdin or `--input-file` (tests, replay) |

Adapters must populate:

- `state.labels` when routing guards or label-based triggers apply.
- `state.change_proposal` (including `head_ref`, `base_ref`, and `head_sha` when
  known) whenever a matched harness needs change-proposal execution context.
  Webhook payloads are often incomplete — adapters should fill gaps via forge
  API calls before dispatch.

### Schedule and manual sources

When `source.system` is `schedule` or `manual`, there is no native webhook
payload. The input driver **must** resolve and populate `entity` (and
`state.change_proposal` when the target is a change proposal) from the scheduled
or operator-specified work item before dispatch proceeds. Schedule drivers must
not emit events with a missing or synthetic entity.

### Transition sub-objects

Transition-specific fields are present only when required by `transition.kind`:

| `transition.kind` | Required sub-object | Forbidden otherwise |
|-------------------|---------------------|---------------------|
| `label_changed` | `label` | `comment`, `review` |
| `comment_added` | `comment` | `label`, `review` |
| `review_submitted` | `review` | `label`, `comment` |
| all other kinds | none | `label`, `comment`, `review` |

The schema enforces these invariants via conditional `required` / `false`
properties.

### Transition kind vocabulary

| Kind | Use |
|------|-----|
| `opened` | Entity created or first opened |
| `reopened` | Entity reopened after close; adapters MAY map to `opened` when the distinction is unnecessary |
| `edited` | Title/body/metadata edit without new commits |
| `synchronized` | Head branch received new commits (GitHub `synchronize`) |
| `updated` | Legacy umbrella; prefer `edited` or `synchronized` for new adapters |
| `closed`, `marked_ready`, `label_changed`, `comment_added`, `review_submitted` | As named |

### Comment extraction

For `comment_added`, adapters extract `command` and `instruction` from the
**raw** comment body before applying the 4096-byte truncation stored in
`comment.body`. This keeps slash-command routing and fix instructions intact even
when the stored body is truncated for transport.

### Actor role mapping

`actor.role` uses forge-neutral permission levels aligned with
[ADR 0054](../../../ADRs/0054-require-authorization-on-all-agent-dispatch-paths.md)
and GitHub collaborator permission names:

| `actor.role` | GitHub permission | Typical use in triggers |
|--------------|-------------------|-------------------------|
| `admin` | admin | Full repo control |
| `maintain` | maintain | Settings without destructive admin |
| `write` | write (member) | Push, label, comment |
| `triage` | triage | Label and moderate without write |
| `read` | read | Read-only collaborator |
| `none` | none | Authenticated user without explicit repo permission (includes many bots) |
| `external` | — | Actor outside the repository (fork PR author, drive-by commenter) |

Adapters populate `role` from the forge collaborator permission API when
available; default to `none` for service accounts without an explicit grant.

### Fork security (`state.change_proposal.is_fork`)

`is_fork` is `true` when `head_repo` differs from `base_repo` (fork-based
change proposal). Write-capable agents (code, fix) that push commits or open
follow-up PRs **must** gate on `!state.change_proposal.is_fork` in harness
`trigger` expressions or rely on dispatch-level authorization per ADR 0054.
Read-only agents (triage, review, retro) may run on fork PRs when policy allows.

## Examples

See [`examples/`](examples/).

## Execution ref projection

`fullsend dispatch` projects each matched harness to the **execution ref**
consumed by existing agent workflows and `fullsend run` (unchanged CLI
contract):

| Execution ref field | Source in `NormalizedEvent` |
|---------------------|----------------------------|
| `source_repo` | `repo` |
| `event_type` | `source.raw_type` |
| `event_payload.issue` | `entity` when `entity.kind == "work_item"`: `{number: entity.id, html_url: entity.url}` |
| `event_payload.pull_request` | See below |
| `event_payload.comment` | `transition.comment` when present: `{body: transition.comment.body}` |
| `trigger_source` (fix agent only) | See below |

**`trigger_source` (fix agent only):** this field is emitted only for the fix
harness execution ref. When `transition.kind == "review_submitted"`, set
`trigger_source` to `transition.review.reviewer_id` (the bot that requested
changes). When `transition.comment.command == "/fs-fix"`, set `trigger_source`
to `actor.id` (the human or bot that invoked the command). Omit
`trigger_source` for all other agents and transitions.

**`event_payload.pull_request`** (GitHub-shaped, for backward compatibility):

When `entity.kind == "change_proposal"`:

```json
{
  "number": "<entity.id>",
  "html_url": "<entity.url>",
  "head": {
    "ref": "<state.change_proposal.head_ref>",
    "sha": "<state.change_proposal.head_sha>",
    "repo": { "full_name": "<state.change_proposal.head_repo>" }
  },
  "base": {
    "ref": "<state.change_proposal.base_ref>",
    "repo": { "full_name": "<state.change_proposal.base_repo>" }
  }
}
```

When `entity.kind == "work_item"` and `entity.linked_change_proposal` is set
(e.g. GitHub `issue_comment` on a PR), emit **both** `issue` from `entity` and
`pull_request` from `linked_change_proposal` + `state.change_proposal` using
the same shape above (`number`/`html_url` from `linked_change_proposal`).

**Change-proposal identity:** when `state.change_proposal` is present,
`state.change_proposal.id` MUST equal `entity.id` if
`entity.kind == "change_proposal"`, or `entity.linked_change_proposal.id` if
the work item carries a linked change proposal. Adapters MUST NOT populate
conflicting IDs across these fields.

Omit `pull_request` when `state.change_proposal` is absent. Omit `issue` when
the event targets only a change proposal with no work-item carrier.

`head.sha` may be omitted in the projected payload when `head_sha` is unset;
downstream workflows may still resolve refs via forge API as a fallback.

No execution-ref field requires information outside this schema when adapters
have populated `state.change_proposal` for change-proposal workloads.
