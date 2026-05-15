# Customizing Agents with Skills

Fullsend agents operate on your repository using Claude Code inside a sandboxed
environment. Because the agents run with your repo checked out, they
automatically pick up any instructions and skills you commit to the repo itself.
No changes to fullsend configuration are needed — you extend agent behavior by
committing files to your own repository.

## How it works

When an agent runs on your repo, Claude Code loads:

1. **`CLAUDE.md`** at the repo root — project-wide instructions that all agents read.
2. **`.claude/commands/`** — custom slash commands available to agents during execution.

Anything you put in these files becomes part of the agent's context. This means
you can shape how triage, code, review, fix, and retro agents behave on your
repo without touching fullsend's harness configuration.

## What to put in CLAUDE.md

`CLAUDE.md` is the simplest way to customize agent behavior. Add instructions
that apply to anyone (human or agent) working in your repo:

```markdown
# CLAUDE.md

## Testing
- Always run `make test` before committing.
- Integration tests require `docker compose up -d` first.

## Code style
- Use structured logging via `slog`. Do not use `log.Printf`.
- All public functions must have doc comments.

## Architecture
- The `internal/api/` package is the HTTP layer. Business logic belongs in `internal/service/`.
- Never import `internal/service/` from `internal/api/` — use interfaces.
```

These instructions influence every agent:

- **Triage** reads them to understand your project's architecture and conventions
  when assessing whether an issue has enough context.
- **Code** follows them when implementing features — it will run `make test`,
  use `slog`, and put code in the right packages.
- **Review** checks PRs against them — if a PR uses `log.Printf`, the review
  agent flags it.
- **Fix** reads them when addressing review feedback to avoid introducing new
  violations while fixing old ones.

## Custom commands

For more structured customization, add command files to `.claude/commands/`.
Each file becomes a slash command the agent can invoke:

```
.claude/commands/
  run-tests.md
  check-migrations.md
  lint-protos.md
```

Example `.claude/commands/run-tests.md`:

```markdown
Run the full test suite for this project:

1. Start dependencies: `docker compose up -d postgres redis`
2. Run migrations: `make db-migrate`
3. Run tests: `make test`
4. Tear down: `docker compose down`
```

## Concrete examples

### Example: Enforcing a migration review checklist

You want the review agent to check every PR that touches database migrations
against a specific checklist. Add to `CLAUDE.md`:

```markdown
## Database migrations
When reviewing PRs that add or modify files in `db/migrations/`:
- Verify the migration is reversible (has both up and down).
- Check that no migration drops a column that is still referenced.
- Confirm the migration number does not conflict with existing ones.
- Flag any `ALTER TABLE` on large tables that could lock production.
```

### Example: Guiding the code agent's test strategy

You want the code agent to write table-driven tests in a specific style:

```markdown
## Test conventions
- Use table-driven tests with `t.Run` subtests.
- Name test cases descriptively: `"returns error when input is empty"`, not `"test1"`.
- Place test helpers in `_test.go` files, not in a `testutil` package.
- Mock external services using interfaces, not monkey-patching.
```

### Example: Steering triage with domain context

Your repo has a complex domain model and triage often miscategorizes issues:

```markdown
## Domain context
- "Reconciler" always refers to the Kubernetes controller in `internal/controller/`.
- "Pipeline" means the CI/CD pipeline, not the data pipeline in `internal/etl/`.
- Issues mentioning "flaky" are almost always about `internal/e2e/` tests.
- The `api/` directory is auto-generated from protobuf — never modify it directly.
```

## Skill shadowing

Each fullsend agent comes with built-in skills that handle specific tasks
during execution. You can **shadow** any of these skills by providing your own
version with the same name. Your version replaces the built-in one at runtime —
no other configuration needed.

This is the most precise way to tune agent behavior. Unlike `CLAUDE.md`
instructions (which are loaded by every agent and consume context for all of
them), a shadowed skill is only loaded by the agent that uses it.

### How it works

Fullsend uses a layered content resolution model. At runtime, the agent's
workspace is assembled by copying upstream defaults first, then overlaying
org-level customizations on top. When you provide a skill with the same name as
a built-in one, yours wins.

To shadow a skill, create it in your `.fullsend` config repo under
`customized/skills/<skill-name>/SKILL.md`. The directory name must match the
built-in skill name exactly.

### Well-known skill names

Each agent's documentation page lists the well-known skill names it uses. These
are the skills you can shadow to customize that agent's behavior:

| Agent | Skill | Purpose |
|-------|-------|---------|
| [Triage](../../agents/triage.md) | `issue-labels` | Label discovery and application during triage |
| [Prioritize](../../agents/prioritize.md) | `customer-research` | Customer data gathering for RICE scoring |
| [Code](../../agents/code.md) | `code-implementation` | Step-by-step implementation procedure |
| [Review](../../agents/review.md) | `code-review`, `pr-review`, `docs-review` | Review evaluation across dimensions |
| [Fix](../../agents/fix.md) | `fix-review` | Review feedback interpretation and fix strategy |
| [Retro](../../agents/retro.md) | `retro-analysis` | Workflow analysis and proposal generation |

See each agent's documentation for concrete examples of shadowed skills.

### When to shadow vs. when to use CLAUDE.md

Use **`CLAUDE.md`** for broad instructions that apply to all agents and human
contributors alike: code style, test conventions, architecture rules.

Use **skill shadowing** when you need to change how a specific agent performs a
specific task — especially when the customization involves domain knowledge,
helper scripts, or external data sources that only one agent needs.

## What not to do

- **Don't put secrets in CLAUDE.md.** It's committed to your repo. Use
  environment variables for anything sensitive.
- **Don't write agent-specific instructions.** All agents read the same
  `CLAUDE.md`, so write instructions as if they're for any contributor.
  This is a feature — the same conventions apply to humans and agents alike.
