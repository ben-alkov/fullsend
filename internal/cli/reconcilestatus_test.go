package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fullsend-ai/fullsend/internal/forge"
	gh "github.com/fullsend-ai/fullsend/internal/forge/github"
)

func TestNewReconcileStatusCmd_RequiredFlags(t *testing.T) {
	cmd := newReconcileStatusCmd()

	for _, name := range []string{"repo", "number", "run-id"} {
		f := cmd.Flags().Lookup(name)
		require.NotNil(t, f, "flag %q should exist", name)
	}
}

func TestNewReconcileStatusCmd_ReasonFlagDefault(t *testing.T) {
	cmd := newReconcileStatusCmd()

	reason := cmd.Flags().Lookup("reason")
	require.NotNil(t, reason)
	assert.Equal(t, "terminated", reason.DefValue)
}

func TestNewReconcileStatusCmd_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing mint-url",
			args:    []string{"--repo", "org/repo", "--number", "7", "--run-id", "run-1"},
			wantErr: "--mint-url or FULLSEND_MINT_URL required",
		},
		{
			name:    "invalid number",
			args:    []string{"--repo", "org/repo", "--number", "0", "--run-id", "run-1"},
			wantErr: "--number must be a positive integer",
		},
		{
			name:    "invalid repo format",
			args:    []string{"--repo", "noslash", "--number", "7", "--run-id", "run-1"},
			wantErr: "--repo must be in owner/repo format",
		},
		{
			name:    "mint-url without role",
			args:    []string{"--repo", "org/repo", "--number", "7", "--run-id", "run-1", "--mint-url", "https://mint.example.com"},
			wantErr: "--role is required when using --mint-url",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newReconcileStatusCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewReconcileStatusCmd_MintURLFlags(t *testing.T) {
	cmd := newReconcileStatusCmd()

	for _, name := range []string{"mint-url", "role"} {
		f := cmd.Flags().Lookup(name)
		require.NotNil(t, f, "flag %q should exist", name)
	}

	mintURL := cmd.Flags().Lookup("mint-url")
	assert.Equal(t, "", mintURL.DefValue)

	role := cmd.Flags().Lookup("role")
	assert.Equal(t, "", role.DefValue)
}

func TestNewReconcileStatusCmd_MintURLFromEnv(t *testing.T) {
	t.Setenv("FULLSEND_MINT_URL", "https://mint.example.com")

	cmd := newReconcileStatusCmd()
	cmd.SetArgs([]string{"--repo", "org/repo", "--number", "7", "--run-id", "run-1", "--role", "review"})
	err := cmd.Execute()
	// Will fail at the OIDC exchange (no ACTIONS_ID_TOKEN_REQUEST_URL), but
	// proves the env var was picked up and --role validation passed.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minting status token")
}

func TestNewReconcileStatusCmd_TokenFlagDeprecated(t *testing.T) {
	cmd := newReconcileStatusCmd()
	f := cmd.Flags().Lookup("token")
	require.NotNil(t, f, "--token flag should exist for backwards compatibility")
	assert.NotEmpty(t, f.Deprecated, "--token flag should be marked deprecated")
}

func TestNewReconcileStatusCmd_DeprecatedTokenExecution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	origNew := newForgeClient
	newForgeClient = func(token string) forge.Client {
		return gh.New(token).WithBaseURL(srv.URL)
	}
	defer func() { newForgeClient = origNew }()

	t.Setenv("FULLSEND_MINT_URL", "")

	cmd := newReconcileStatusCmd()
	cmd.SetArgs([]string{
		"--repo", "org/repo",
		"--number", "7",
		"--run-id", "run-1",
		"--token", "test-token",
	})

	err := cmd.Execute()
	require.NoError(t, err)
}

func TestNewReconcileStatusCmd_DeprecatedTokenCancelledReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	origNew := newForgeClient
	newForgeClient = func(token string) forge.Client {
		return gh.New(token).WithBaseURL(srv.URL)
	}
	defer func() { newForgeClient = origNew }()

	t.Setenv("FULLSEND_MINT_URL", "")

	cmd := newReconcileStatusCmd()
	cmd.SetArgs([]string{
		"--repo", "org/repo",
		"--number", "7",
		"--run-id", "run-1",
		"--reason", "cancelled",
		"--token", "test-token",
	})

	err := cmd.Execute()
	require.NoError(t, err)
}
