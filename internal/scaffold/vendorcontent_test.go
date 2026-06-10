package scaffold

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectVendoredAssetsUsesDefaultsMirror(t *testing.T) {
	root, err := moduleRootFromScaffold()
	require.NoError(t, err)

	files, err := CollectVendoredAssets(root, "")
	require.NoError(t, err)

	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}

	assert.Contains(t, paths, ".defaults/action.yml")
	assert.Contains(t, paths, ".defaults/.github/actions/mint-token/action.yml")
	assert.Contains(t, paths, ".defaults/internal/scaffold/fullsend-repo/agents/triage.md")
	assert.Contains(t, paths, ".github/workflows/reusable-triage.yml")
	assert.NotContains(t, paths, "action.yml")
	assert.NotContains(t, paths, "agents/triage.md")
	assert.NotContains(t, paths, ".defaults/.github/workflows/reusable-triage.yml")
}

func TestVendoredMarkerPath(t *testing.T) {
	assert.Equal(t, ".defaults/action.yml", VendoredMarkerPath())
}
