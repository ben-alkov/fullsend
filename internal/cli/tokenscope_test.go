package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchTokenScope_ReturnsRepoNames(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/installation/repositories", r.URL.Path)
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		assert.Equal(t, "Bearer ghs_test_token", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_count": 2,
			"repositories": []map[string]string{
				{"full_name": "org-a/repo-one"},
				{"full_name": "org-a/repo-two"},
			},
		})
	}))
	defer github.Close()

	repos, err := fetchTokenScope("ghs_test_token", github.URL)
	require.NoError(t, err)
	assert.Equal(t, []string{"org-a/repo-one", "org-a/repo-two"}, repos)
}

func TestFetchTokenScope_EmptyToken(t *testing.T) {
	repos, err := fetchTokenScope("", "https://unused")
	require.NoError(t, err)
	assert.Nil(t, repos)
}

func TestFetchTokenScope_NonInstallationToken_401(t *testing.T) {
	// Non-installation tokens get 401. Treated as "not an installation
	// token" — returns (nil, nil), not an error.
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer github.Close()

	repos, err := fetchTokenScope("ghs_bad", github.URL)
	assert.NoError(t, err)
	assert.Nil(t, repos)
}

func TestFetchTokenScope_NonInstallationToken_403(t *testing.T) {
	// PATs and GITHUB_TOKENs return 403 on /installation/repositories.
	// Treated as "not an installation token" — silent, no error.
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer github.Close()

	repos, err := fetchTokenScope("ghp_personal", github.URL)
	assert.NoError(t, err)
	assert.Nil(t, repos)
}

func TestFetchTokenScope_UnexpectedStatus(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer github.Close()

	repos, err := fetchTokenScope("ghs_token", github.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
	assert.Nil(t, repos)
}
