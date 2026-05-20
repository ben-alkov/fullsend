package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInferenceCommand_HasSubcommands(t *testing.T) {
	cmd := newInferenceCmd()
	names := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["provision-wif"], "expected provision-wif subcommand")
	assert.True(t, names["status"], "expected status subcommand")
}

func TestInferenceCommand_RegisteredInRoot(t *testing.T) {
	cmd := newRootCmd()
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "inference" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected inference subcommand registered in root")
}

// --- provision-wif tests ---

func TestInferenceProvisionWIFCmd_RequiresArg(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

func TestInferenceProvisionWIFCmd_RequiresProject(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")
}

func TestInferenceProvisionWIFCmd_Flags(t *testing.T) {
	cmd := newInferenceProvisionWIFCmd()

	projectFlag := cmd.Flags().Lookup("project")
	require.NotNil(t, projectFlag, "expected --project flag")

	regionFlag := cmd.Flags().Lookup("region")
	require.NotNil(t, regionFlag, "expected --region flag")
	assert.Equal(t, "global", regionFlag.DefValue)

	poolFlag := cmd.Flags().Lookup("pool")
	require.NotNil(t, poolFlag, "expected --pool flag")
	assert.Equal(t, "fullsend-pool", poolFlag.DefValue)

	providerFlag := cmd.Flags().Lookup("provider")
	require.NotNil(t, providerFlag, "expected --provider flag")
	assert.Equal(t, "github-oidc", providerFlag.DefValue)

	dryRunFlag := cmd.Flags().Lookup("dry-run")
	require.NotNil(t, dryRunFlag, "expected --dry-run flag")
}

func TestInferenceProvisionWIFCmd_DetectsOrgMode(t *testing.T) {
	// Org-scoped: arg without "/"
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme",
		"--project", "my-project",
		"--dry-run"})
	err := cmd.Execute()
	// Should succeed (dry-run prints what would happen)
	require.NoError(t, err)
}

func TestInferenceProvisionWIFCmd_DetectsRepoMode(t *testing.T) {
	// Repo-scoped: arg with "/"
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme/widget",
		"--project", "my-project",
		"--dry-run"})
	err := cmd.Execute()
	// Should succeed (dry-run prints what would happen)
	require.NoError(t, err)
}

func TestInferenceProvisionWIFCmd_DryRunOrgSucceeds(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme",
		"--project", "my-project",
		"--dry-run"})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestInferenceProvisionWIFCmd_DryRunRepoSucceeds(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme/widget",
		"--project", "my-project",
		"--dry-run"})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestInferenceProvisionWIFCmd_DryRunCustomPool(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme",
		"--project", "my-project",
		"--pool", "custom-pool",
		"--provider", "custom-provider",
		"--dry-run"})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestInferenceProvisionWIFCmd_RejectsInvalidOrgName(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "-invalid",
		"--project", "my-project"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestInferenceProvisionWIFCmd_RejectsInvalidRepoFormat(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme/",
		"--project", "my-project"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestInferenceProvisionWIFCmd_DoesNotRequireGitHubToken(t *testing.T) {
	// Unset all GitHub tokens to prove they're not needed.
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")

	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "provision-wif", "acme",
		"--project", "my-project",
		"--dry-run"})
	err := cmd.Execute()
	// Should not fail with "no GitHub token found"
	require.NoError(t, err)
}

// --- status tests ---

func TestInferenceStatusCmd_RequiresArg(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "status"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

func TestInferenceStatusCmd_RequiresProject(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "status", "acme"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")
}

func TestInferenceStatusCmd_Flags(t *testing.T) {
	cmd := newInferenceStatusCmd()

	projectFlag := cmd.Flags().Lookup("project")
	require.NotNil(t, projectFlag, "expected --project flag")

	regionFlag := cmd.Flags().Lookup("region")
	require.NotNil(t, regionFlag, "expected --region flag")
	assert.Equal(t, "global", regionFlag.DefValue)

	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag, "expected --format flag")
	assert.Equal(t, "text", formatFlag.DefValue)
}

func TestInferenceStatusCmd_RejectsInvalidFormat(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "status", "acme",
		"--project", "my-project",
		"--format", "yaml"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--format must be one of: text, json, env")
}

func TestInferenceStatusCmd_DoesNotRequireGitHubToken(t *testing.T) {
	// Unset all GitHub tokens to prove they're not needed.
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")

	// Status without dry-run will try to reach GCP, which will fail,
	// but it should NOT fail with "no GitHub token found".
	cmd := newRootCmd()
	cmd.SetArgs([]string{"inference", "status", "acme",
		"--project", "my-project"})
	err := cmd.Execute()
	if err != nil {
		assert.NotContains(t, err.Error(), "no GitHub token found")
	}
}

// --- parseOrgOrRepo tests ---

func TestParseOrgOrRepo_OrgMode(t *testing.T) {
	org, repo, err := parseOrgOrRepo("acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", org)
	assert.Equal(t, "", repo)
}

func TestParseOrgOrRepo_RepoMode(t *testing.T) {
	org, repo, err := parseOrgOrRepo("acme/widget")
	require.NoError(t, err)
	assert.Equal(t, "acme", org)
	assert.Equal(t, "acme/widget", repo)
}

func TestParseOrgOrRepo_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty owner in repo", "/widget", "invalid"},
		{"empty repo in repo", "acme/", "invalid"},
		{"leading hyphen", "-acme", "hyphen"},
		{"trailing hyphen", "acme-", "hyphen"},
		{"invalid chars", "ac me", "invalid"},
		{"dots in owner", "ac.me/widget", "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseOrgOrRepo(tc.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// --- formatStatusJSON tests ---

func TestFormatStatusJSON(t *testing.T) {
	result := &inferenceStatusResult{
		Status:      "healthy",
		ProjectID:   "my-project",
		WIFProvider: "projects/123/locations/global/workloadIdentityPools/fullsend-pool/providers/github-oidc",
		Region:      "global",
	}

	output, err := formatStatusJSON(result)
	require.NoError(t, err)

	var parsed map[string]string
	err = json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "healthy", parsed["status"])
	assert.Equal(t, "my-project", parsed["FULLSEND_GCP_PROJECT_ID"])
	assert.Equal(t, "projects/123/locations/global/workloadIdentityPools/fullsend-pool/providers/github-oidc", parsed["FULLSEND_GCP_WIF_PROVIDER"])
	assert.Equal(t, "global", parsed["FULLSEND_GCP_REGION"])
}

// --- formatStatusEnv tests ---

func TestFormatStatusEnv(t *testing.T) {
	result := &inferenceStatusResult{
		Status:      "healthy",
		ProjectID:   "my-project",
		WIFProvider: "projects/123/locations/global/workloadIdentityPools/fullsend-pool/providers/github-oidc",
		Region:      "global",
	}

	output := formatStatusEnv(result)
	assert.Contains(t, output, "FULLSEND_GCP_PROJECT_ID=my-project")
	assert.Contains(t, output, "FULLSEND_GCP_WIF_PROVIDER=projects/123/locations/global/workloadIdentityPools/fullsend-pool/providers/github-oidc")
	assert.Contains(t, output, "FULLSEND_GCP_REGION=global")
	// env format should not contain status decoration
	assert.NotContains(t, output, "Status:")
}
