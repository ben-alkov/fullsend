# Customizing Agents

This guide explains how to customize fullsend agents for your organization and repositories through harness configurations and layered content resolution.

## Harness Configuration

Each agent run is configured by a harness YAML file that defines the complete execution environment. These files live in the `.fullsend` config repo (per-org mode) or `.fullsend/customized/harness/` (per-repo mode).

### Harness YAML Structure

```yaml
agent: agents/coder.md           # Agent definition (Claude agent file)
image: ghcr.io/fullsend/sandbox  # Container image for sandbox
model: claude-sonnet-4-6         # Inference model
policy: policies/coder.yaml      # Security policy
timeout_minutes: 30              # Max execution time

skills:                          # Skills loaded into agent
  - skills/git.md
  - skills/github-pr.md

plugins:                         # Claude Code plugins (list of plugin names)
  - plugins/gopls-lsp

providers:                       # Inference providers (list of provider names)
  - vertex

host_files:                      # Files copied into sandbox
  - src: ${GITHUB_WORKSPACE}/.fullsend/customized/scripts/
    dest: /tmp/workspace/scripts/
    optional: true
  - src: configs/tool-config.json
    dest: /tmp/workspace/.config/tool-config.json
    expand: true                 # Expand ${VAR} in file content

pre_script: scripts/pre-code.sh    # Runs on host before agent
post_script: scripts/post-code.sh  # Runs on host after agent

runner_env:                      # Env vars passed to runner (key-value map)
  GITHUB_TOKEN: "${GH_TOKEN}"
  FULLSEND_OUTPUT_DIR: "${RUNNER_TEMP}/output"

validation_loop:                 # Iterative validation
  script: scripts/validate-output-schema.sh
  max_iterations: 3
  feedback_mode: stderr          # Feed script stderr as feedback

security:
  enabled: true
  fail_mode: closed              # "closed" (default) or "open"
  host_scanners:                 # Scanners run before sandbox creation
    unicode_normalizer: true     # Strip invisible chars, NFKC normalization
    context_injection: true      # Detect prompt injection patterns
    ssrf_validator: true         # Check URLs in payloads
    secret_redactor: true        # Redact secrets from input
    llm_guard:                   # ML-based injection detection
      enabled: true
      threshold: 0.92
      match_type: sentence       # "sentence" or "full"
  sandbox_hooks:                 # Hooks during agent execution
    tirith:                      # Terminal security scanner
      enabled: true
      fail_on: high              # "critical", "high", or "medium"
    ssrf_pretool: true           # SSRF check before tool use
    secret_redact_posttool: true # Redact secrets after tool use
    unicode_posttool: true       # Unicode normalization after tool use
    context_suppress_posttool: true  # Suppress context in error messages
    canary_pretool: true         # Canary injection detection
    canary_posttool: true        # Canary leakage detection
  escalation:                    # Action on critical findings
    on_critical: halt            # "halt" or "review"
    review_label: requires-manual-review
  trace:                         # Trace ID for correlation
    enabled: true
```

## Layered Configuration Resolution

Fullsend uses a three-tier inheritance model for all configuration: agent definitions, skills, policies, harness definitions, and guardrails. Each tier can extend or override the one below it.

```
┌──────────────────────────────────────────────────────────────┐
│              Configuration Layering (ADR 0035)                │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Priority (highest wins):                                    │
│                                                              │
│  ┌──────────────────────┐                                    │
│  │ Per-repo overrides   │  .fullsend/customized/{dir}/       │
│  │ (target repo)        │  in the target repository          │
│  └──────────┬───────────┘                                    │
│             │ overrides                                      │
│  ┌──────────▼───────────┐                                    │
│  │ Org-level overrides  │  customized/{dir}/                 │
│  │ (.fullsend config    │  in the .fullsend config repo      │
│  │  repo)               │                                    │
│  └──────────┬───────────┘                                    │
│             │ overrides                                      │
│  ┌──────────▼───────────┐                                    │
│  │ Upstream defaults    │  Provided at runtime by reusable   │
│  │ (fullsend-ai/        │  workflow workspace preparation    │
│  │  fullsend)           │                                    │
│  └──────────────────────┘                                    │
│                                                              │
│  Layered directories:                                        │
│    agents/  skills/  schemas/  harness/                      │
│    policies/  scripts/  env/                                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Customization Directory Structure

Orgs customize layered directories by placing overrides in `customized/` subdirectories:

```
.fullsend/                          (config repo)
├── customized/
│   ├── agents/                     → Override agent definitions
│   ├── skills/                     → Add/override skills
│   ├── schemas/                    → Override output schemas
│   ├── harness/                    → Override harness configs
│   ├── policies/                   → Override security policies
│   ├── scripts/                    → Override hook scripts
│   └── env/                        → Override environment files
└── .github/workflows/              → Reusable workflows
```

For per-repo mode, the same structure lives at `.fullsend/customized/` within the target repo.

## Agent Roles

Each agent role has its own identity, permissions, and purpose:

```
┌─────────────────────────────────────────────────────────────┐
│                   Agent Role Architecture                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Role          GitHub App                  Purpose          │
│  ─────         ──────────                  ───────          │
│  fullsend      {org}-fullsend[bot]         Dispatch/control │
│  triage        {org}-triage[bot]           Issue triage     │
│  coder         {org}-coder[bot]            Code generation  │
│  review        {org}-review[bot]           PR review        │
│  fix           (reuses coder app)          Fix failures     │
│  retro         {org}-retro[bot]            Retrospectives   │
│  prioritize    {org}-prioritize[bot]       Backlog priority │
│                                                             │
│  App naming: {org}-{role}                                   │
│  Bot naming: {org}-{role}[bot]                              │
│  PEM storage: GCP Secret Manager                            │
│  Secret name: fullsend-{org}--{role}-app-pem                │
│                                                             │
│  Note: "fix" role reuses the "coder" app — no separate      │
│  GitHub App is created for it.                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Customization Examples

### Adding a Custom Skill

Create `.fullsend/customized/skills/my-skill.md` in your config repo:

```markdown
# My Custom Skill

Custom domain knowledge for this organization.

## Examples

...
```

The skill will be automatically available to all agents that include `skills/my-skill.md` in their harness configuration.

### Overriding an Agent Definition

Create `.fullsend/customized/agents/coder.md` to override the default coder agent with org-specific instructions:

```markdown
# Code Agent (Customized)

[Custom instructions for your org...]
```

### Customizing Harness Configuration

Create `.fullsend/customized/harness/coder.yaml` to modify the coder agent's execution environment:

```yaml
# Extend the upstream coder harness
agent: agents/coder.md
model: claude-opus-4-6  # Use Opus instead of Sonnet
timeout_minutes: 45     # Increase timeout for complex tasks

# Add org-specific skills
skills:
  - skills/git.md
  - skills/github-pr.md
  - skills/my-custom-linting.md  # Org-specific skill

# Custom validation
validation_loop:
  script: scripts/custom-validate.sh
  max_iterations: 5
```

### Per-Repo Overrides

Target repos can override org-level customizations by placing files in `.fullsend/customized/` within the repo:

```
my-repo/
├── .fullsend/
│   └── customized/
│       ├── agents/coder.md        # Repo-specific agent instructions
│       ├── skills/repo-skill.md   # Repo-specific skill
│       └── harness/coder.yaml     # Repo-specific harness config
```

## See Also

- [Installation Guide](../admin/installation.md) - Initial setup
- [Bugfix Workflow](bugfix-workflow.md) - How agents work together
- [ADR 0035: Layered Content Resolution](../../ADRs/0035-layered-content-resolution.md)
