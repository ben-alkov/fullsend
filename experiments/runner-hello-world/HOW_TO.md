# How to run the experiment

## Two-repo model

This experiment uses a two-repo setup that mirrors the production layout:

- **`.fullsend` repo** (`test-fullsend/.fullsend`): Contains the harness definition, agents, skills, env files, policies, scripts, and the GitHub Actions workflow. This is where the workflow runs.
- **Target repo** (`test-fullsend/test-repo`): The codebase the agent analyzes. Checked out by the workflow and passed to the CLI via `--target-repo`.

The `run-experiment.sh` script syncs the `.fullsend/` directory and workflow to the `.fullsend` repo, then triggers the workflow with the target repo as an input.

## Requirements

### Local (to run the experiment)

- **Go toolchain** (1.23+)
- **gh CLI** authenticated with access to the fullsend fork and both repos in the target org
- **podman** (for building and pushing the container image)
- **rsync**
- A local clone of the `.fullsend` repo (see below)

### Repos

The default setup uses the `test-fullsend` org with two repos:

- `test-fullsend/.fullsend` — harness and workflow (secrets configured here)
- `test-fullsend/test-repo` — target codebase for the agent

The `.fullsend` repo needs **GitHub secrets** configured (see [Setting up GCP secrets](#setting-up-gcp-secrets) below) and a **GitHub release** on your fullsend fork (used to distribute the binary to the runner).

### Setting up GCP secrets

The experiment uses Claude Code via Vertex AI, which requires a GCP project with the Vertex AI API enabled and a service account key.

**If you already use Claude Code via Vertex AI locally** (i.e. `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION` are set in your environment), you already have a GCP project with the Vertex AI API enabled — skip step 1 and reuse your project ID and region for the secrets in step 4:

```bash
gh secret set GCP_PROJECT --repo your-org/.fullsend --body "${ANTHROPIC_VERTEX_PROJECT_ID}"
gh secret set GCP_REGION --repo your-org/.fullsend --body "${CLOUD_ML_REGION}"
```

You still need a service account key for CI (steps 2-4), since the workflow can't use interactive authentication like `gcloud auth application-default login`.

**If you need to set up Vertex AI from scratch**, follow all steps below:

1. **Create or select a GCP project** with the [Vertex AI API](https://console.cloud.google.com/apis/library/aiplatform.googleapis.com) enabled.

2. **Create a service account** with the `Vertex AI User` role:
   ```bash
   gcloud iam service-accounts create fullsend-runner \
     --display-name="Fullsend Runner" \
     --project=${ANTHROPIC_VERTEX_PROJECT_ID}

   gcloud projects add-iam-policy-binding ${ANTHROPIC_VERTEX_PROJECT_ID} \
     --member="serviceAccount:fullsend-runner@${ANTHROPIC_VERTEX_PROJECT_ID}.iam.gserviceaccount.com" \
     --role="roles/aiplatform.user" \
     --condition=None
   ```

3. **Create and download a JSON key**:
   ```bash
   gcloud iam service-accounts keys create /tmp/sa-key.json \
     --iam-account=fullsend-runner@${ANTHROPIC_VERTEX_PROJECT_ID}.iam.gserviceaccount.com
   ```

4. **Set the secrets on the `.fullsend` repo** (where the workflow runs):
   ```bash
   gh secret set GCP_SA_KEY --repo your-org/.fullsend < /tmp/sa-key.json
   gh secret set GCP_PROJECT --repo your-org/.fullsend --body "${ANTHROPIC_VERTEX_PROJECT_ID}"
   gh secret set GCP_REGION --repo your-org/.fullsend --body "${CLOUD_ML_REGION}"
   ```

5. **Delete the local key file** (it's now stored as a GitHub secret):
   ```bash
   rm /tmp/sa-key.json
   ```

Available regions for Claude on Vertex AI include `us-east5`, `europe-west1`, and `asia-southeast1`. Check the [Vertex AI documentation](https://cloud.google.com/vertex-ai/generative-ai/docs/partner-models/use-claude#regions) for the latest list.

### GitHub Actions runner

The workflow installs these automatically:

- **fullsend** binary (from a GitHub release)
- **OpenShell** CLI

Claude Code and experiment tool binaries are pre-installed in the container image (`quay.io/manonru/fullsend-exp`), which the sandbox is created from via `--from`.

## Quick start (using defaults)

```bash
# Clone the .fullsend repo (one-time setup)
git clone git@github.com:test-fullsend/.fullsend.git /tmp/dot-fullsend

# Run the experiment (builds image, pushes to quay.io, syncs, triggers workflow)
./experiments/runner-hello-world/experiment/run-experiment.sh
```

The script will print the workflow run URL. You can watch it with:

```bash
gh run watch <RUN_ID> --repo test-fullsend/.fullsend
```

## Using a different org

To run against your own org, edit the variables at the top of `experiment/run-experiment.sh`:

```bash
FULLSEND_REPO="/tmp/your-dot-fullsend"    # Local clone of your .fullsend repo
RELEASE_REPO="your-user/fullsend"         # Where to upload the fullsend binary
RELEASE_TAG="runner-hello-world-dev"       # Release tag name
WORKFLOW_REPO="your-org/.fullsend"         # Where to trigger the workflow
WORKFLOW_FILE="hello-world.yml"            # Workflow file name
TARGET_REPO="your-org/your-target-repo"    # Target repo for the agent
IMAGE_REPO="quay.io/your-user/your-image"  # Container image registry
```

Then update the workflow file (`experiment/workflow/hello-world.yml`) to point the fullsend install step at your release:

```yaml
- name: Install fullsend
  run: |
    curl -LsSf https://github.com/your-user/fullsend/releases/download/runner-hello-world-dev/fullsend_dev_linux_amd64.tar.gz -o /tmp/fullsend.tar.gz
    sudo tar xzf /tmp/fullsend.tar.gz -C /usr/local/bin/
```

Steps:

1. Create two repos in your org: `.fullsend` and a target repo with some content
2. Create a GitHub release on your fullsend fork: `gh release create runner-hello-world-dev --repo your-user/fullsend --title "Dev" --notes "Dev build"`
3. Set the required secrets on the `.fullsend` repo (see [Setting up GCP secrets](#setting-up-gcp-secrets))
4. Clone the `.fullsend` repo locally: `git clone git@github.com:your-org/.fullsend.git /tmp/your-dot-fullsend`
5. Run `./experiments/runner-hello-world/experiment/run-experiment.sh`
