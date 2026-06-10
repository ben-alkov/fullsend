package layers

import (
	"context"
	"fmt"

	"github.com/fullsend-ai/fullsend/internal/forge"
	"github.com/fullsend-ai/fullsend/internal/scaffold"
	"github.com/fullsend-ai/fullsend/internal/ui"
)

// VendorFunc uploads vendored binary and content when --vendor is set.
type VendorFunc func(ctx context.Context, client forge.Client, printer *ui.Printer, owner, repo string) error

// VendorBinaryLayer manages vendored binary and content assets.
//
// When enabled (--vendor), it calls VendorFunc to upload binary and content.
// When disabled, it removes stale vendored assets from prior installs.
type VendorBinaryLayer struct {
	org      string
	repo     string
	client   forge.Client
	ui       *ui.Printer
	enabled  bool
	vendorFn VendorFunc
}

// Compile-time check that VendorBinaryLayer implements Layer.
var _ Layer = (*VendorBinaryLayer)(nil)

// NewVendorBinaryLayer creates a new VendorBinaryLayer.
func NewVendorBinaryLayer(org, repo string, client forge.Client, printer *ui.Printer, enabled bool, vendorFn VendorFunc) *VendorBinaryLayer {
	return &VendorBinaryLayer{
		org:      org,
		repo:     repo,
		client:   client,
		ui:       printer,
		enabled:  enabled,
		vendorFn: vendorFn,
	}
}

func (l *VendorBinaryLayer) Name() string { return "vendor" }

func (l *VendorBinaryLayer) binaryPath() string {
	if l.repo != forge.ConfigRepoName {
		return VendoredBinaryPathPerRepo
	}
	return VendoredBinaryPath
}

func (l *VendorBinaryLayer) perRepo() bool {
	return l.repo != forge.ConfigRepoName
}

// RequiredScopes returns the scopes needed for the given operation.
func (l *VendorBinaryLayer) RequiredScopes(op Operation) []string {
	switch op {
	case OpInstall:
		return []string{"repo"}
	default:
		return nil
	}
}

// Install either vendors assets (when enabled) or removes stale ones.
func (l *VendorBinaryLayer) Install(ctx context.Context) error {
	if l.enabled {
		if l.vendorFn == nil {
			return fmt.Errorf("vendor function not configured")
		}
		return l.vendorFn(ctx, l.client, l.ui, l.org, l.repo)
	}

	path := l.binaryPath()
	_, err := l.client.GetFileContent(ctx, l.org, l.repo, path)
	if err != nil && !forge.IsNotFound(err) {
		return fmt.Errorf("checking for vendored binary: %w", err)
	}
	if err == nil {
		l.ui.StepStart("removing stale vendored binary")
		deleteMsg := RemoveStaleBinaryCommitMessage(path)
		if err := l.client.DeleteFile(ctx, l.org, l.repo, path, deleteMsg); err != nil {
			l.ui.StepFail("failed to remove vendored binary")
			return fmt.Errorf("deleting vendored binary: %w", err)
		}
		l.ui.StepDone("removed stale vendored binary")
	}

	pathPrefix := ""
	if l.perRepo() {
		pathPrefix = ".fullsend/"
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
	for _, p := range paths {
		_, err := l.client.GetFileContent(ctx, l.org, l.repo, p)
		if err != nil {
			if forge.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("checking for vendored content at %s: %w", p, err)
		}
		l.ui.StepStart("removing stale vendored content")
		deleteMsg := RemoveStaleContentCommitMessage(p)
		if err := l.client.DeleteFile(ctx, l.org, l.repo, p, deleteMsg); err != nil {
			l.ui.StepFail("failed to remove vendored content")
			return fmt.Errorf("deleting vendored content at %s: %w", p, err)
		}
		removed++
	}
	if removed > 0 {
		l.ui.StepDone(fmt.Sprintf("removed %d stale vendored content files", removed))
	}
	return nil
}

func (l *VendorBinaryLayer) Uninstall(_ context.Context) error { return nil }

func (l *VendorBinaryLayer) Analyze(ctx context.Context) (*LayerReport, error) {
	report := &LayerReport{Name: l.Name()}

	marker := scaffold.VendoredMarkerPath()

	_, markerErr := l.client.GetFileContent(ctx, l.org, l.repo, marker)
	if markerErr != nil && !forge.IsNotFound(markerErr) {
		return nil, fmt.Errorf("checking vendored marker at %s: %w", marker, markerErr)
	}
	hasMarker := markerErr == nil

	_, binErr := l.client.GetFileContent(ctx, l.org, l.repo, l.binaryPath())
	if binErr != nil && !forge.IsNotFound(binErr) {
		return nil, fmt.Errorf("checking vendored binary: %w", binErr)
	}
	hasBinary := binErr == nil

	switch {
	case l.enabled:
		if hasBinary || hasMarker {
			report.Status = StatusInstalled
			if hasBinary {
				report.Details = append(report.Details, fmt.Sprintf("vendored binary present at %s", l.binaryPath()))
			}
			if hasMarker {
				report.Details = append(report.Details, "vendored content marker present")
			}
		} else {
			report.Status = StatusNotInstalled
			report.WouldInstall = append(report.WouldInstall, "upload vendored binary and content")
		}
	case hasBinary || hasMarker:
		report.Status = StatusDegraded
		if hasBinary {
			report.Details = append(report.Details, fmt.Sprintf("stale vendored binary at %s", l.binaryPath()))
			report.WouldFix = append(report.WouldFix, "delete vendored binary")
		}
		if hasMarker {
			report.Details = append(report.Details, "stale vendored content present")
			report.WouldFix = append(report.WouldFix, "delete vendored content")
		}
	default:
		report.Status = StatusInstalled
		report.Details = append(report.Details, "no vendored assets present")
	}

	return report, nil
}
