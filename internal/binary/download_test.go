package binary

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSourceTreeRejectsOversizedFile(t *testing.T) {
	origMax := maxDownloadSize
	maxDownloadSize = 64
	t.Cleanup(func() { maxDownloadSize = origMax })

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "fullsend-repo/large.bin",
		Typeflag: tar.TypeReg,
		Size:     128,
		Mode:     0o644,
	}))
	_, err := tw.Write(bytes.Repeat([]byte("x"), 128))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	dest := t.TempDir()
	err = extractSourceTree(bytes.NewReader(buf.Bytes()), dest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestExtractSourceTreeExtractsSmallFile(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	content := []byte("hello")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "fullsend-repo/README.md",
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
		Mode:     0o644,
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	dest := t.TempDir()
	require.NoError(t, extractSourceTree(bytes.NewReader(buf.Bytes()), dest))

	data, err := os.ReadFile(filepath.Join(dest, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, content, data)
}
