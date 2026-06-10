package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fullsend-ai/fullsend/internal/binary"
	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/layers"
	"github.com/fullsend-ai/fullsend/internal/scaffold"
	"github.com/fullsend-ai/fullsend/internal/ui"
)

const vendorArch = binary.DefaultArch

func validateVendorFlags(vendor bool, fullsendBinary, fullsendSource string) error {
	if fullsendBinary != "" && !vendor {
		return fmt.Errorf("--fullsend-binary requires --vendor")
	}
	if fullsendSource != "" && !vendor {
		return fmt.Errorf("--fullsend-source requires --vendor")
	}
	return nil
}

func addVendorFlags(cmd *cobra.Command, vendor *bool, fullsendBinary, fullsendSource *string) {
	cmd.Flags().BoolVar(vendor, "vendor", false, "vendor binary, reusable workflows, actions, and agent content for CI")
	cmd.Flags().StringVar(fullsendBinary, "fullsend-binary", "", "path to a Linux fullsend binary to upload when vendoring (default: auto-resolve)")
	cmd.Flags().StringVar(fullsendSource, "fullsend-source", "", "fullsend source checkout for content and cross-compile (default: auto-detect or GitHub fetch)")
}

// makeVendorFunc returns a VendorFunc closure that uploads vendored assets.
func makeVendorFunc(fullsendBinary, fullsendSource string) layers.VendorFunc {
	return func(ctx context.Context, client forge.Client, printer *ui.Printer, owner, repo string) error {
		return acquireAndVendor(ctx, client, printer, owner, repo, fullsendBinary, fullsendSource)
	}
}

func acquireAndVendor(ctx context.Context, client forge.Client, printer *ui.Printer, owner, repo, fullsendBinary, fullsendSource string) error {
	perRepo := repo != forge.ConfigRepoName
	pathPrefix := ""
	if perRepo {
		pathPrefix = ".fullsend/"
	}
	destPath := layers.VendoredBinaryPath
	if perRepo {
		destPath = layers.VendoredBinaryPathPerRepo
	}

	root, err := binary.ResolveVendorRoot(fullsendSource, version)
	if err != nil {
		printer.StepFail("Failed to resolve fullsend source")
		return err
	}
	if root.Cleanup != nil {
		defer root.Cleanup()
	}

	var (
		binPath string
		source  binary.Source
		tmpDir  string
	)

	if fullsendBinary != "" {
		printer.StepStart(fmt.Sprintf("Using provided binary: %s", fullsendBinary))
		if err := binary.ResolveExplicit(fullsendBinary, vendorArch); err != nil {
			printer.StepFail("Invalid --fullsend-binary")
			return fmt.Errorf("validating --fullsend-binary: %w", err)
		}
		binPath = fullsendBinary
		source = binary.SourceExplicitPath
		printer.StepDone("Validated linux/amd64 ELF binary")
	} else {
		result, err := binary.ResolveForVendor(binary.VendorOpts{
			SourceDir: fullsendSource,
			Version:   version,
			Arch:      vendorArch,
		})
		if err != nil {
			printer.StepFail("Failed to obtain binary for vendoring")
			return err
		}
		tmpDir = result.TmpDir
		binPath = result.Path
		source = result.Source
	}

	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}

	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("stat binary: %w", err)
	}

	printer.StepStart(fmt.Sprintf("Uploading vendored binary to %s", destPath))
	binMsg := layers.VendorCommitMessage(source, version, destPath, info.Size())
	if err := layers.VendorBinary(ctx, client, owner, repo, destPath, binPath, binMsg); err != nil {
		printer.StepFail("Failed to upload vendored binary")
		return err
	}
	printer.StepDone(fmt.Sprintf("Uploaded vendored binary (%d MB)", info.Size()/(1024*1024)))

	assets, err := scaffold.CollectVendoredAssets(root.Path, pathPrefix)
	if err != nil {
		printer.StepFail("Failed to collect vendored content")
		return fmt.Errorf("collecting vendored content: %w", err)
	}

	var files []forge.TreeFile
	for _, f := range assets {
		files = append(files, forge.TreeFile{
			Path:    f.Path,
			Content: f.Content,
			Mode:    f.Mode,
		})
	}

	printer.StepStart(fmt.Sprintf("Uploading %d vendored content files", len(files)))
	contentMsg := layers.VendorContentCommitMessage(version, pathPrefix, len(files))
	committed, err := client.CommitFiles(ctx, owner, repo, contentMsg, files)
	if err != nil {
		printer.StepFail("Failed to upload vendored content")
		return fmt.Errorf("committing vendored content: %w", err)
	}
	if committed {
		printer.StepDone(fmt.Sprintf("Uploaded %d vendored content files", len(files)))
	} else {
		printer.StepDone("Vendored content up to date")
	}

	return nil
}

func removeStaleVendoredAssets(ctx context.Context, client forge.Client, printer *ui.Printer, owner, repo string, perRepo bool) error {
	pathPrefix := ""
	if perRepo {
		pathPrefix = ".fullsend/"
	}

	destPath := layers.VendoredBinaryPath
	if perRepo {
		destPath = layers.VendoredBinaryPathPerRepo
	}
	if err := removeStaleVendoredBinary(ctx, client, printer, owner, repo, destPath); err != nil {
		return err
	}

	paths, err := scaffold.ManagedVendoredContentPaths(pathPrefix)
	if err != nil {
		return fmt.Errorf("enumerating vendored content paths: %w", err)
	}

	legacy, err := scaffold.LegacyFlatVendoredPaths(pathPrefix)
	if err != nil {
		return fmt.Errorf("enumerating legacy vendored paths: %w", err)
	}
	paths = append(paths, legacy...)

	var removed int
	for _, path := range paths {
		_, err := client.GetFileContent(ctx, owner, repo, path)
		if err != nil {
			if forge.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("checking for vendored content at %s: %w", path, err)
		}
		deleteMsg := layers.RemoveStaleContentCommitMessage(path)
		if err := client.DeleteFile(ctx, owner, repo, path, deleteMsg); err != nil {
			return fmt.Errorf("deleting vendored content at %s: %w", path, err)
		}
		removed++
	}

	if removed > 0 {
		printer.StepDone(fmt.Sprintf("Removed %d stale vendored content files", removed))
	}
	return nil
}

func removeStaleVendoredBinary(ctx context.Context, client forge.Client, printer *ui.Printer, owner, repo, destPath string) error {
	_, err := client.GetFileContent(ctx, owner, repo, destPath)
	if err != nil {
		if forge.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("checking for vendored binary: %w", err)
	}

	printer.StepStart("removing stale vendored binary")
	deleteMsg := layers.RemoveStaleBinaryCommitMessage(destPath)
	if err := client.DeleteFile(ctx, owner, repo, destPath, deleteMsg); err != nil {
		printer.StepFail("failed to remove vendored binary")
		return fmt.Errorf("deleting vendored binary: %w", err)
	}
	printer.StepDone("removed stale vendored binary")
	return nil
}

func vendorDryRunMessage(fullsendBinary, fullsendSource, destPath string) string {
	if fullsendBinary != "" {
		msg := fmt.Sprintf("Would upload provided binary from %s to %s", fullsendBinary, destPath)
		if fullsendSource != "" {
			msg += fmt.Sprintf("; content from %s", fullsendSource)
		}
		return msg
	}
	if fullsendSource != "" {
		return fmt.Sprintf("Would cross-compile from %s and upload vendored binary and content", fullsendSource)
	}
	if _, err := binary.ModuleRoot(); err == nil {
		return fmt.Sprintf("Would cross-compile and upload vendored binary and content to %s", destPath)
	}
	if binary.IsReleasedVersion(version) {
		return fmt.Sprintf("Would download release %s source/binary and upload vendored assets to %s", version, destPath)
	}
	return fmt.Sprintf("Would fail: dev CLI outside checkout cannot vendor to %s", destPath)
}
