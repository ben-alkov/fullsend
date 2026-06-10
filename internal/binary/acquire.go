package binary

import (
	"fmt"
	"os"
	"path/filepath"
)

// Source identifies how a Linux fullsend binary was obtained.
type Source int

const (
	SourceExplicitPath Source = iota
	SourceCheckoutBuild
	SourceReleaseDownload
)

// AcquireResult holds the path to an acquired binary and metadata for callers.
type AcquireResult struct {
	TmpDir string // caller must RemoveAll when non-empty
	Path   string
	Source Source
}

// ResolveExplicit validates that path is a Linux ELF for arch.
func ResolveExplicit(path, arch string) error {
	return ValidateLinuxBinary(path, arch)
}

// ResolveForRun obtains a Linux binary using the run policy:
// release download (if released) → cross-compile → latest release.
func ResolveForRun(version, arch string) (AcquireResult, error) {
	tmpDir, err := os.MkdirTemp("", "fullsend-linux-*")
	if err != nil {
		return AcquireResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	binaryPath := filepath.Join(tmpDir, "fullsend")

	// 1. Released version → download matching release asset.
	if IsReleasedVersion(version) {
		fmt.Fprintf(os.Stderr, "Downloading fullsend %s for linux/%s from GitHub Release...\n", version, arch)
		if dlErr := DownloadRelease(version, arch, binaryPath); dlErr == nil {
			fmt.Fprintf(os.Stderr, "Downloaded fullsend for linux/%s\n", arch)
			return AcquireResult{TmpDir: tmpDir, Path: binaryPath, Source: SourceReleaseDownload}, nil
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: release download failed: %v\n", dlErr)
		}
	}

	// 2. Try cross-compilation (requires Go toolchain + module checkout).
	fmt.Fprintf(os.Stderr, "Cross-compiling fullsend for linux/%s...\n", arch)
	if ccErr := CrossCompile(CrossCompileOpts{
		Version:      version,
		Arch:         arch,
		DestPath:     binaryPath,
		VersionStamp: "-crosscompiled",
	}); ccErr == nil {
		fmt.Fprintf(os.Stderr, "Cross-compiled fullsend for linux/%s\n", arch)
		return AcquireResult{TmpDir: tmpDir, Path: binaryPath, Source: SourceCheckoutBuild}, nil
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: cross-compilation failed: %v\n", ccErr)
	}

	// 3. Last resort → download latest release.
	fmt.Fprintf(os.Stderr, "Downloading latest fullsend release for linux/%s...\n", arch)
	latestErr := DownloadLatestRelease(arch, binaryPath)
	if latestErr == nil {
		fmt.Fprintf(os.Stderr, "Downloaded latest fullsend for linux/%s\n", arch)
		return AcquireResult{TmpDir: tmpDir, Path: binaryPath, Source: SourceReleaseDownload}, nil
	}
	fmt.Fprintf(os.Stderr, "WARNING: latest release download failed: %v\n", latestErr)

	os.RemoveAll(tmpDir)
	return AcquireResult{}, fmt.Errorf("all strategies failed for linux/%s: provide --fullsend-binary or install Go toolchain", arch)
}

// VendorOpts configures binary resolution for vendoring.
type VendorOpts struct {
	SourceDir string
	Version   string
	Arch      string
}

// ResolveForVendor obtains a Linux binary using the vendoring policy:
// cross-compile from resolved source root → matching release (released CLI only) → fail.
func ResolveForVendor(opts VendorOpts) (AcquireResult, error) {
	tmpDir, err := os.MkdirTemp("", "fullsend-linux-*")
	if err != nil {
		return AcquireResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	binaryPath := filepath.Join(tmpDir, "fullsend")

	root, rootErr := ResolveVendorRoot(opts.SourceDir, opts.Version)
	if rootErr == nil {
		if root.Cleanup != nil {
			defer root.Cleanup()
		}
		fmt.Fprintf(os.Stderr, "Cross-compiling fullsend for linux/%s...\n", opts.Arch)
		if ccErr := CrossCompile(CrossCompileOpts{
			Version:      opts.Version,
			Arch:         opts.Arch,
			DestPath:     binaryPath,
			VersionStamp: "-vendored",
			SourceDir:    root.Path,
		}); ccErr == nil {
			fmt.Fprintf(os.Stderr, "Cross-compiled fullsend for linux/%s\n", opts.Arch)
			return AcquireResult{TmpDir: tmpDir, Path: binaryPath, Source: SourceCheckoutBuild}, nil
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: cross-compilation failed: %v\n", ccErr)
		}
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: could not resolve source root: %v\n", rootErr)
	}

	if IsReleasedVersion(opts.Version) {
		fmt.Fprintf(os.Stderr, "Downloading fullsend %s for linux/%s from GitHub Release...\n", opts.Version, opts.Arch)
		if dlErr := DownloadRelease(opts.Version, opts.Arch, binaryPath); dlErr == nil {
			fmt.Fprintf(os.Stderr, "Downloaded fullsend for linux/%s\n", opts.Arch)
			return AcquireResult{TmpDir: tmpDir, Path: binaryPath, Source: SourceReleaseDownload}, nil
		} else {
			os.RemoveAll(tmpDir)
			return AcquireResult{}, fmt.Errorf("cross-compilation unavailable and release download failed for v%s: %w", opts.Version, dlErr)
		}
	}

	os.RemoveAll(tmpDir)
	return AcquireResult{}, fmt.Errorf("cannot vendor binary: not in fullsend source tree and CLI version %s is a dev build — use --fullsend-binary, --fullsend-source, run from a checkout, or use a released CLI", opts.Version)
}
