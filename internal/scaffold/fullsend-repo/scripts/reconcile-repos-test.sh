#!/usr/bin/env bash
# reconcile-repos-test.sh - Regression tests for reconcile-repos.sh.
#
# Uses mocked gh/yq/base64 commands so tests do not hit GitHub.
# Run from the repo root: bash internal/scaffold/fullsend-repo/scripts/reconcile-repos-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONCILE_SCRIPT="${SCRIPT_DIR}/reconcile-repos.sh"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

CONFIG_DIR="${TMPDIR}/config"
MOCK_BIN="${TMPDIR}/bin"
GH_LOG="${TMPDIR}/gh-calls.log"
COMMIT_MSGS_LOG="${TMPDIR}/commit-msgs.log"
mkdir -p "${CONFIG_DIR}/templates" "${MOCK_BIN}"

cat > "${CONFIG_DIR}/config.yaml" <<'EOF'
version: 1
repos:
  test-repo:
    enabled: true
  new-repo:
    enabled: true
  refresh-repo:
    enabled: true
  removed-repo:
    enabled: false
EOF

cat > "${CONFIG_DIR}/templates/shim-workflow-call.yaml" <<'EOF'
fresh shim template
EOF

cat > "${MOCK_BIN}/base64" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-w0" ]]; then
  shift
fi
/usr/bin/base64 "$@" | tr -d '\r\n'
EOF
chmod +x "${MOCK_BIN}/base64"

cat > "${MOCK_BIN}/yq" <<'EOF'
#!/usr/bin/env bash
query="${1:-}"
if [[ "$query" == *"enabled == true"* ]]; then
  printf '%s\n' "test-repo" "new-repo" "refresh-repo"
elif [[ "$query" == *"enabled == false"* ]]; then
  echo "removed-repo"
else
  echo "unexpected yq query: $*" >&2
  exit 1
fi
EOF
chmod +x "${MOCK_BIN}/yq"

cat > "${MOCK_BIN}/gh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gh' >> "${GH_LOG}"
for arg in "\$@"; do
  printf ' %q' "\$arg" >> "${GH_LOG}"
done
printf '\n' >> "${GH_LOG}"

# Handle pr subcommands.
if [[ "\$1" == "pr" ]]; then
  case "\$2" in
    list)
      # Parse --repo and --head to differentiate responses.
      repo_arg=""
      head_arg=""
      prev=""
      for arg in "\$@"; do
        case "\$prev" in
          --repo) repo_arg="\$arg" ;;
          --head) head_arg="\$arg" ;;
        esac
        prev="\$arg"
      done
      if [[ "\$head_arg" == "fullsend/onboard" ]]; then
        case "\$repo_arg" in
          test-org/test-repo)
            echo "https://github.com/test-org/test-repo/pull/18" ;;
          test-org/refresh-repo)
            echo "https://github.com/test-org/refresh-repo/pull/5" ;;
        esac
      fi
      exit 0
      ;;
    create)
      echo "https://github.com/test-org/mock/pull/99"
      exit 0
      ;;
    close)
      exit 0
      ;;
  esac
  exit 0
fi

if [[ "\$1" != "api" ]]; then
  echo "unexpected gh command: \$*" >&2
  exit 1
fi

# Extract flags from the gh api call.
jq_filter=""
has_input=false
method="GET"
field_message=""
shift  # consume "api"
endpoint="\$1"; shift
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --jq) jq_filter="\$2"; shift 2 ;;
    --input) has_input=true; shift 2 ;;  # consume --input -
    --method) method="\$2"; shift 2 ;;
    --field)
      if [[ "\$2" == message=* ]]; then
        field_message="\${2#message=}"
      fi
      shift 2
      ;;
    --silent) shift ;;
    *) shift ;;
  esac
done

# Capture commit messages from stdin for the git/commits endpoint.
input_data=""
if [[ "\$has_input" == "true" ]]; then
  input_data=\$(cat)
  if [[ "\$endpoint" == */git/commits ]]; then
    printf '%s\0' "\$input_data" >> "${COMMIT_MSGS_LOG}"
  fi
fi

json=""
rc=0
case "\$endpoint" in
  repos/test-org/*/actions/variables/*)
    # Variable not found — 404 for all test repos.
    json='{"status":"404","message":"Not Found"}'
    rc=1
    ;;
  repos/test-org/test-repo/contents/*)
    # test-repo: stale shim exists on default branch.
    json='{"content":"c3RhbGUgc2hpbSB0ZW1wbGF0ZQo=","sha":"file-sha"}'
    ;;
  repos/test-org/removed-repo/contents/*)
    if [[ "\$method" == "DELETE" ]]; then
      # Capture the removal commit message for validation.
      if [[ -n "\$field_message" ]]; then
        removal_json=\$(jq -n --arg msg "\$field_message" '{message: \$msg}')
        printf '%s\0' "\$removal_json" >> "${COMMIT_MSGS_LOG}"
      fi
    else
      # Shim exists — return content and SHA for GET requests.
      json='{"content":"c3RhbGUgc2hpbSB0ZW1wbGF0ZQo=","sha":"remove-file-sha"}'
    fi
    ;;
  repos/test-org/*/contents/*)
    # new-repo, refresh-repo: no shim on default branch.
    rc=1
    ;;
  repos/test-org/*/git/ref/heads/*)
    json='{"object":{"sha":"base-sha"}}'
    ;;
  repos/test-org/*/git/commits/base-sha)
    json='{"tree":{"sha":"base-tree-sha"}}'
    ;;
  repos/test-org/*/git/blobs)
    json='{"sha":"blob-sha"}'
    ;;
  repos/test-org/*/git/trees)
    json='{"sha":"tree-sha"}'
    ;;
  repos/test-org/*/git/commits)
    json='{"sha":"desired-commit-sha"}'
    ;;
  repos/test-org/*/git/refs)
    # Branch creation — fail so the script falls back to PATCH.
    rc=1
    ;;
  repos/test-org/*/git/refs/heads/*)
    # Branch update or delete — always succeed.
    rc=0
    ;;
  repos/test-org/*)
    # Repo metadata (default branch, visibility).
    json='{"default_branch":"main","private":false}'
    ;;
  *)
    echo "unexpected gh api endpoint: \$endpoint" >&2
    exit 1
    ;;
esac

if [[ -n "\$json" ]]; then
  if [[ -n "\$jq_filter" ]]; then
    printf '%s' "\$json" | jq -r "\$jq_filter"
  else
    printf '%s\n' "\$json"
  fi
fi
exit "\$rc"
EOF
chmod +x "${MOCK_BIN}/gh"

export PATH="${MOCK_BIN}:${PATH}"
export GITHUB_REPOSITORY_OWNER="test-org"
export GITHUB_SHA="test-sha"
export GH_TOKEN="fake-token"

bash "${RECONCILE_SCRIPT}" "${CONFIG_DIR}" > "${TMPDIR}/stdout.log" 2>&1

if grep -q "refs/heads/fullsend/onboard.*sha=base-sha" "${GH_LOG}"; then
  echo "FAIL: fullsend/onboard was reset to the default branch SHA"
  cat "${GH_LOG}"
  exit 1
fi

if ! grep -q "refs/heads/fullsend/onboard.*sha=desired-commit-sha" "${GH_LOG}"; then
  echo "FAIL: fullsend/onboard was not moved directly to the desired shim commit"
  cat "${GH_LOG}"
  exit 1
fi

if grep -q "contents/.github/workflows/fullsend.yaml.*--method PUT" "${GH_LOG}"; then
  echo "FAIL: shim update used Contents API after resetting branch state"
  cat "${GH_LOG}"
  exit 1
fi

echo "PASS: stale shim branch update is atomic"

# ===========================
# Test: commit messages include a non-trivial body
# ===========================

if [ ! -f "${COMMIT_MSGS_LOG}" ]; then
  echo "FAIL: no commit messages were captured"
  exit 1
fi

# The log contains null-delimited JSON payloads from git/commits calls
# and Contents API DELETE calls (removal path).
# Extract each message and verify it has a subject, blank line, and body.
msg_index=0
fail=0
while IFS= read -r -d '' json_payload; do
  [ -z "$json_payload" ] && continue
  msg=$(printf '%s' "$json_payload" | jq -r '.message')
  msg_index=$((msg_index + 1))

  # A well-formed message has: subject, blank line, body.
  subject=$(printf '%s\n' "$msg" | head -n1)
  second_line=$(printf '%s\n' "$msg" | sed -n '2p')
  body=$(printf '%s\n' "$msg" | tail -n +3)

  if [ -n "$second_line" ]; then
    echo "FAIL: commit message #${msg_index} missing blank line after subject"
    echo "  subject: $subject"
    echo "  line 2: $second_line"
    fail=1
    continue
  fi

  body_trimmed=$(printf '%s' "$body" | tr -d '[:space:]')
  if [ -z "$body_trimmed" ]; then
    echo "FAIL: commit message #${msg_index} has no body"
    echo "  subject: $subject"
    fail=1
    continue
  fi

  # Verify subject does not exceed 50 characters (conventional commit guideline).
  if [ "${#subject}" -gt 50 ]; then
    echo "FAIL: commit message #${msg_index} subject exceeds 50 chars"
    echo "  subject (${#subject} chars): $subject"
    fail=1
  fi

  # Verify no line in the message exceeds 72 characters.
  while IFS= read -r bline; do
    if [ "${#bline}" -gt 72 ]; then
      echo "FAIL: commit message #${msg_index} has a line exceeding 72 chars"
      echo "  line (${#bline} chars): $bline"
      fail=1
    fi
  done <<< "$msg"
done < "${COMMIT_MSGS_LOG}"

if [ "$msg_index" -eq 0 ]; then
  echo "FAIL: no commit messages found in log"
  exit 1
fi

# Expect exactly 4 commit messages: update (stale shim), refresh (existing PR),
# add (new enrollment), and remove (unenrollment).
if [ "$msg_index" -ne 4 ]; then
  echo "FAIL: expected 4 commit messages but found $msg_index"
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  echo "--- captured commit messages ---"
  cat "${COMMIT_MSGS_LOG}"
  exit 1
fi

echo "PASS: commit messages include a non-trivial body (≤72 chars/line)"
