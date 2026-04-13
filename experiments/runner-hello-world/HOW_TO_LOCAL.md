# How to run `fullsend run` locally

This guide explains how to run the `fullsend run` CLI command on your local machine against a target repository.

## Prerequisites

- **Go toolchain** (1.23+)
- **OpenShell** installed and in PATH
- **Docker** (required by OpenShell — Podman is not supported)
- **GCP credentials** for Vertex AI (if using the hello-world experiment)

## Install Docker

OpenShell requires Docker. Podman is not supported. Install Docker CE and make sure the daemon is running:

```bash
# Fedora
sudo dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io

# Start the daemon
sudo systemctl start docker
sudo systemctl enable docker

# Allow your user to run docker without sudo
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker info
```

## Install OpenShell

```bash
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.0.30/install.sh | sh
openshell --version
```

## Build fullsend

From the repository root:

```bash
go build -o ~/.local/bin/fullsend ./cmd/fullsend/
fullsend --version
```

## Required environment variables

The hello-world experiment requires these environment variables on the host:

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project with Vertex AI API enabled |
| `CLOUD_ML_REGION` | GCP region (e.g. `us-east5`, `europe-west1`) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account key JSON |

If you already use Claude Code via Vertex AI locally, `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION` are likely already set. For `GOOGLE_APPLICATION_CREDENTIALS`, you can use a service account key file or the Application Default Credentials from gcloud:

```bash
gcloud auth application-default login
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/application_default_credentials.json
```

## Pre-pull the sandbox image

The first sandbox creation will time out if the image hasn't been pulled yet. Pull it in advance:

```bash
docker pull quay.io/manonru/fullsend-exp:latest
```

## Running the agent

```bash
fullsend run hello-world \
  --fullsend-dir /path/to/experiments/runner-hello-world/.fullsend \
  --target-repo /path/to/your-repo \
  --output-dir /tmp/fullsend-output
```

### CLI flags

| Flag | Required | Default | Purpose |
|------|----------|---------|---------|
| `--fullsend-dir` | yes | | Base directory containing the `.fullsend` layout |
| `--target-repo` | yes | | Path to the target repository |
| `--output-dir` | no | `/tmp/fullsend` | Base directory for run output (per-invocation subdirectories are created under it) |

## Inspecting results

After a run, output is organized under the `--output-dir` directory:

```
/tmp/fullsend-output/
  agent-hello-world-<pid>-<timestamp>/
    iteration-1/
      output/          # Files the agent produced (hello-world.md, summary.md)
      transcripts/     # Claude transcript .jsonl files
    iteration-2/       # Only if validation retried
      output/
      transcripts/
```

The CLI prints the full run directory path at the end:

```
Run directory    /tmp/fullsend-output/agent-hello-world-12345-1713200000
Agent exit code  0
Agent runs       1
Validation       passed
```

## Troubleshooting

- **"openshell not found in PATH"**: Install OpenShell (see above).
- **"sandbox not ready after 1m0s"**: The sandbox image hasn't been pulled yet. Run `docker pull quay.io/manonru/fullsend-exp:latest` first (see above).
- **"Docker socket exists but the daemon is not responding"**: Run `sudo systemctl start docker`.
- **"permission denied while trying to connect to the Docker daemon"**: Your user is not in the `docker` group. Run `sudo usermod -aG docker $USER` and start a new shell session.
- **"host variable X is not set"**: A required environment variable is missing. Check the table above.
- **Validation failures**: Check `iteration-N/output/` for the agent's output files. The validation script (`scripts/validate-output.sh`) runs on the host and checks for expected files.
