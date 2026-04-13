# Runner Hello World Experiment

A minimal end-to-end test of the `fullsend run` CLI. It provisions an OpenShell sandbox from a pre-built container image, runs a Claude Code agent inside it, extracts output, and validates the result with a retry loop.

## What it does

1. Reads the harness definition (`harness/hello-world.yaml`)
2. Creates an OpenShell sandbox from a pre-built container image (`quay.io/manonru/fullsend-exp`) and applies a network policy (Vertex AI access)
3. Bootstraps the sandbox with the agent definition, skills, env vars, and GCP credentials
4. Copies the target repository into the sandbox
5. Runs a Claude Code agent that executes a hello-world tool and summarizes the repository
6. Extracts output files and runs validation (with configurable retries)
7. Extracts transcripts and prints results

## Key design decisions

- **Container image over SCP**: Tool binaries (`hello-world-bin`) and Claude Code are pre-installed in the container image rather than copied via SCP at runtime. This makes sandboxes self-contained and faster to provision.
- **OpenShell base image**: The container image extends `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`, which is required by OpenShell for custom sandbox images.
- **Two output files**: The agent produces `output/hello-world.md` (from the tool binary) and `output/summary.md` (from the skill). Validation checks both.
- **Vertex AI via service account key**: GCP credentials are injected as a host file with env-var expansion, not via OpenShell providers (see [vertex-auth-flow.md](vertex-auth-flow.md) for details).

## What's not tested

The following CLI features are implemented but not exercised by this experiment:

- **Pre/post scripts** (`pre_script`, `post_script`): Host-side scripts that run before sandbox creation and after sandbox cleanup. No scripts are configured in this harness.
- **Providers**: OpenShell credential providers. This experiment uses host_files for GCP credentials instead.
- **API servers**: Host-side REST proxy servers. Not used in this experiment.
- **Agent input**: Additional input files copied to the sandbox. Not used.
- **Feedback mode**: `validation_loop.feedback_mode` for feeding validation output back to the agent. Not configured.

## Directory layout

```
experiments/runner-hello-world/
  README.md                              # This file
  HOW_TO.md                              # How to reproduce the experiment (CI)
  HOW_TO_LOCAL.md                        # How to run fullsend locally
  vertex-auth-flow.md                    # Vertex AI auth design notes
  .fullsend/                             # Production layout (synced to test repo)
    agents/hello-world.md                #   Agent definition
    env/
      gcp-vertex.env                     #   Sandbox env: Vertex AI credentials
      repo.env                           #   Sandbox env: repo-specific vars
    harness/hello-world.yaml             #   Harness: wires agent, skills, image, policy
    policies/hello-world.yaml            #   Network policy (allows googleapis.com)
    scripts/
      validate-output.sh                 #   Validation script (runs on host)
    skills/hello-world-summary/
      SKILL.md                           #   Skill: explore repo and write summary
  experiment/                            # Experiment-only files (not synced to test repo)
    run-experiment.sh                    #   Build + deploy + trigger script
    Containerfile                        #   Container image (Claude Code + tool binaries)
    tools/hello-world-bin                #   Shell script: writes output (baked into image)
    workflow/hello-world.yml             #   GitHub Actions workflow (copied to test repo)
```

The `.fullsend/` directory mirrors the layout expected in production: harness definitions, agents, skills, env files, policies, and scripts. The `experiment/` directory contains files only needed to build and run this experiment (container image, run script, workflow).

## Creating new agents

When creating a new agent for fullsend, prefer baking tool binaries and dependencies into the sandbox container image rather than copying them at runtime via SCP. This makes sandboxes self-contained and reproducible.

If your agent needs tools that are scripts rather than compiled binaries, you can deliver them via `host_files` in the harness YAML:

```yaml
host_files:
  - src: scripts/my-tool.sh
    dest: /tmp/workspace/bin/my-tool.sh
```

If a script is specifically crafted for use by a skill, bundle it inside the skill directory (e.g. `skills/my-skill/scripts/run.sh`) rather than using `host_files`. Fullsend copies the entire skill directory recursively into the sandbox, including `scripts/`, `references/`, and `assets/` subdirectories, following the [agentskills.io specification](https://agentskills.io/specification).

### Sandbox environment variables

Fullsend sets the following environment variables inside the sandbox:

| Variable | Value | Purpose |
|----------|-------|---------|
| `FULLSEND_OUTPUT_DIR` | `/tmp/workspace/output` | Directory where the agent should write output files. Extracted to the host after each iteration. Cleared between iterations in a validation loop. |
| `FULLSEND_TARGET_REPO_DIR` | `/tmp/workspace/<repo-name>` | Path to the target repository inside the sandbox. The agent starts with this as its working directory. |
| `CLAUDE_CONFIG_DIR` | `/tmp/claude-config` | Claude configuration directory. Agent and skill definitions are placed here automatically. |

## How to reproduce

See [HOW_TO.md](HOW_TO.md) for prerequisites, GCP setup, and step-by-step instructions to run the experiment via CI.

See [HOW_TO_LOCAL.md](HOW_TO_LOCAL.md) for instructions to run `fullsend run` locally.
