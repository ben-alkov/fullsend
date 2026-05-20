package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fullsend-ai/fullsend/internal/dispatch/gcf"
	"github.com/fullsend-ai/fullsend/internal/ui"
)

func newInferenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inference",
		Short: "Manage inference credentials (requires GCP access)",
		Long: `Commands for provisioning and inspecting inference WIF infrastructure.

These commands only require GCP project access — no GitHub token or
mint project is needed. Use them to set up Workload Identity Federation
for Vertex AI inference, then hand off the WIF provider resource name
to the GitHub admin who runs 'fullsend github setup'.`,
	}
	cmd.AddCommand(newInferenceProvisionWIFCmd())
	cmd.AddCommand(newInferenceStatusCmd())
	return cmd
}

// parseOrgOrRepo determines whether the argument is an org name or owner/repo.
// Returns (org, "", nil) for org-scoped or (owner, "owner/repo", nil) for repo-scoped.
func parseOrgOrRepo(arg string) (org string, repo string, err error) {
	if strings.Contains(arg, "/") {
		parts := strings.SplitN(arg, "/", 2)
		owner, repoName := parts[0], parts[1]
		if owner == "" || repoName == "" {
			return "", "", fmt.Errorf("invalid repo format: expected owner/repo, got %q", arg)
		}
		if !githubOwnerPattern.MatchString(owner) {
			return "", "", fmt.Errorf("invalid owner name %q: must contain only alphanumeric characters and hyphens", owner)
		}
		if !githubRepoPattern.MatchString(repoName) {
			return "", "", fmt.Errorf("invalid repo name %q: must contain only alphanumeric characters, hyphens, dots, or underscores", repoName)
		}
		return owner, arg, nil
	}

	if err := validateOrgName(arg); err != nil {
		return "", "", err
	}
	return arg, "", nil
}

func newInferenceProvisionWIFCmd() *cobra.Command {
	var project string
	var region string
	var pool string
	var provider string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "provision-wif <org|owner/repo>",
		Short: "Create WIF infrastructure for inference",
		Long: `Provisions Workload Identity Federation infrastructure in a GCP project
for GitHub Actions to authenticate and access Vertex AI.

Org-scoped mode (e.g. 'fullsend inference provision-wif acme'):
  Creates a WIF pool and provider scoped to all repos in the org.

Repo-scoped mode (e.g. 'fullsend inference provision-wif acme/widget'):
  Creates a WIF pool and a dedicated provider scoped to a single repo.

After provisioning, prints the WIF provider resource name for handoff
to the GitHub admin who runs 'fullsend github setup'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required")
			}

			org, repo, err := parseOrgOrRepo(args[0])
			if err != nil {
				return err
			}

			printer := ui.New(os.Stdout)

			if dryRun {
				return runInferenceProvisionWIFDryRun(cmd, printer, org, repo, project, region, pool, provider)
			}

			return runInferenceProvisionWIF(cmd, printer, org, repo, project, region, pool, provider)
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "GCP project ID for Vertex AI (required)")
	cmd.Flags().StringVar(&region, "region", "global", "WIF location (default: global)")
	cmd.Flags().StringVar(&pool, "pool", "fullsend-pool", "WIF pool name")
	cmd.Flags().StringVar(&provider, "provider", "github-oidc", "WIF provider name")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without making them")

	return cmd
}

func runInferenceProvisionWIFDryRun(cmd *cobra.Command, printer *ui.Printer, org, repo, project, region, pool, provider string) error {
	printer.Banner()
	printer.Blank()

	if repo != "" {
		printer.Header("Dry run: provision WIF for repo-scoped inference")
		printer.Blank()
		printer.StepInfo(fmt.Sprintf("Repository:   %s", repo))
		providerID := gcf.BuildRepoProviderID(strings.SplitN(repo, "/", 2)[0], strings.SplitN(repo, "/", 2)[1])
		printer.StepInfo(fmt.Sprintf("WIF provider: %s (repo-scoped)", providerID))
		printer.StepInfo(fmt.Sprintf("Condition:    assertion.repository == '%s'", repo))
	} else {
		printer.Header("Dry run: provision WIF for org-scoped inference")
		printer.Blank()
		printer.StepInfo(fmt.Sprintf("Organization: %s", org))
		printer.StepInfo(fmt.Sprintf("WIF provider: %s (org-scoped)", provider))
		printer.StepInfo(fmt.Sprintf("Condition:    assertion.repository_owner == '%s'", org))
	}

	printer.Blank()
	printer.StepInfo(fmt.Sprintf("GCP project:  %s", project))
	printer.StepInfo(fmt.Sprintf("WIF location: %s", region))
	printer.StepInfo(fmt.Sprintf("WIF pool:     %s", pool))
	printer.Blank()
	printer.StepInfo("Would create/update:")
	printer.StepInfo("  - Service account: fullsend-mint")
	printer.StepInfo(fmt.Sprintf("  - WIF pool: %s", pool))
	printer.StepInfo("  - WIF OIDC provider")
	printer.StepInfo("  - IAM binding: roles/aiplatform.user")
	printer.Blank()

	return nil
}

func runInferenceProvisionWIF(cmd *cobra.Command, printer *ui.Printer, org, repo, project, region, pool, provider string) error {
	printer.Banner()
	printer.Blank()

	if repo != "" {
		printer.Header("Provisioning WIF for repo-scoped inference: " + repo)
	} else {
		printer.Header("Provisioning WIF for org-scoped inference: " + org)
	}
	printer.Blank()

	ctx := cmd.Context()

	gcpClient := gcf.NewLiveGCFClient()
	provisioner := gcf.NewProvisioner(gcf.Config{
		ProjectID:   project,
		GitHubOrgs:  []string{org},
		Repo:        repo,
		WIFPoolName: pool,
		WIFProvider: provider,
	}, gcpClient)

	printer.StepStart("Provisioning WIF infrastructure")
	wifProvider, err := provisioner.ProvisionWIF(ctx)
	if err != nil {
		printer.StepFail("WIF provisioning failed")
		return fmt.Errorf("provisioning WIF for inference: %w", err)
	}
	printer.StepDone("WIF infrastructure ready")
	printer.Blank()

	printer.KeyValue("WIF Provider", wifProvider)
	printer.Blank()

	// Print suggested next command.
	targetArg := org
	if repo != "" {
		targetArg = repo
	}
	printer.StepInfo("Pass this value to the GitHub setup command:")
	printer.StepInfo(fmt.Sprintf("  fullsend github setup %s \\", targetArg))
	printer.StepInfo(fmt.Sprintf("    --inference-project=%s \\", project))
	printer.StepInfo(fmt.Sprintf("    --inference-wif-provider=%s \\", wifProvider))
	printer.StepInfo(fmt.Sprintf("    --inference-region=%s", region))
	printer.Blank()
	printer.StepWarn("IAM policy changes may take up to 7 minutes to propagate")
	printer.Blank()

	return nil
}

// inferenceStatusResult holds the data returned by the status command.
type inferenceStatusResult struct {
	Status      string
	ProjectID   string
	WIFProvider string
	Region      string
	Details     []string // human-readable status lines
}

func newInferenceStatusCmd() *cobra.Command {
	var project string
	var region string
	var format string

	cmd := &cobra.Command{
		Use:   "status <org|owner/repo>",
		Short: "Check inference WIF health and print config",
		Long: `Checks the health of inference WIF infrastructure and displays
configuration values for handoff to the GitHub admin.

Use --format=env to print KEY=value pairs suitable for copying.
Use --format=json to get a machine-readable status + config output.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required")
			}

			switch format {
			case "text", "json", "env":
				// valid
			default:
				return fmt.Errorf("--format must be one of: text, json, env (got %q)", format)
			}

			org, repo, err := parseOrgOrRepo(args[0])
			if err != nil {
				return err
			}

			return runInferenceStatus(cmd, org, repo, project, region, format)
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "GCP project ID for Vertex AI (required)")
	cmd.Flags().StringVar(&region, "region", "global", "WIF location (default: global)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, env")

	return cmd
}

func runInferenceStatus(cmd *cobra.Command, org, repo, project, region, format string) error {
	ctx := cmd.Context()
	gcpClient := gcf.NewLiveGCFClient()

	poolName := "fullsend-pool"
	providerName := "github-oidc"
	if repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		providerName = gcf.BuildRepoProviderID(parts[0], parts[1])
	}

	result := &inferenceStatusResult{
		ProjectID: project,
		Region:    region,
	}

	// Step 1: Look up project number.
	projectNumber, err := gcpClient.GetProjectNumber(ctx, project)
	if err != nil {
		result.Status = "error"
		result.Details = append(result.Details, fmt.Sprintf("Failed to get project number: %v", err))
		return outputStatus(cmd, result, format)
	}
	result.Details = append(result.Details, "Project number: "+projectNumber)

	// Step 2: Check WIF provider exists.
	providerInfo, err := gcpClient.GetWIFProvider(ctx, projectNumber, poolName, providerName)
	if err != nil {
		result.Status = "error"
		result.Details = append(result.Details, fmt.Sprintf("Failed to check WIF provider: %v", err))
		return outputStatus(cmd, result, format)
	}

	if providerInfo == nil {
		result.Status = "not_provisioned"
		result.Details = append(result.Details, fmt.Sprintf("WIF pool %q or provider %q not found", poolName, providerName))
		result.Details = append(result.Details, "Run 'fullsend inference provision-wif' to create the infrastructure")
		return outputStatus(cmd, result, format)
	}

	// Step 3: Build WIF provider resource name.
	wifProvider := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, poolName, providerName)
	result.WIFProvider = wifProvider

	// Step 4: Parse attribute condition for validation.
	condition := providerInfo.AttributeCondition
	result.Details = append(result.Details, "WIF provider: "+wifProvider)
	result.Details = append(result.Details, "Attribute condition: "+condition)

	if repo != "" {
		expected := fmt.Sprintf("assertion.repository == '%s'", strings.ToLower(repo))
		if condition == expected {
			result.Details = append(result.Details, "Condition matches repo: OK")
		} else {
			result.Details = append(result.Details, fmt.Sprintf("Condition mismatch: expected %q", expected))
		}
	} else {
		if strings.Contains(condition, org) {
			result.Details = append(result.Details, "Condition includes org: OK")
		} else {
			result.Details = append(result.Details, fmt.Sprintf("Condition does not include org %q", org))
		}
	}

	result.Status = "healthy"
	return outputStatus(cmd, result, format)
}

func outputStatus(cmd *cobra.Command, result *inferenceStatusResult, format string) error {
	switch format {
	case "json":
		output, err := formatStatusJSON(result)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), output)
	case "env":
		fmt.Fprint(cmd.OutOrStdout(), formatStatusEnv(result))
	default:
		printer := ui.New(cmd.OutOrStdout())
		printer.Banner()
		printer.Blank()
		printer.Header("Inference Status")
		printer.Blank()

		switch result.Status {
		case "healthy":
			printer.StepDone("Status: healthy")
		case "not_provisioned":
			printer.StepFail("Status: not provisioned")
		default:
			printer.StepFail("Status: " + result.Status)
		}

		for _, detail := range result.Details {
			printer.StepInfo(detail)
		}

		printer.Blank()
		if result.WIFProvider != "" {
			printer.Header("Config values for handoff")
			printer.Blank()
			printer.KeyValue("FULLSEND_GCP_PROJECT_ID", result.ProjectID)
			printer.KeyValue("FULLSEND_GCP_WIF_PROVIDER", result.WIFProvider)
			printer.KeyValue("FULLSEND_GCP_REGION", result.Region)
			printer.Blank()
		}
	}

	if result.Status != "healthy" {
		return fmt.Errorf("inference status: %s", result.Status)
	}
	return nil
}

func formatStatusJSON(result *inferenceStatusResult) (string, error) {
	data := map[string]string{
		"status":                    result.Status,
		"FULLSEND_GCP_PROJECT_ID":   result.ProjectID,
		"FULLSEND_GCP_WIF_PROVIDER": result.WIFProvider,
		"FULLSEND_GCP_REGION":       result.Region,
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling status JSON: %w", err)
	}
	return string(b), nil
}

func formatStatusEnv(result *inferenceStatusResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("FULLSEND_GCP_PROJECT_ID=%s\n", result.ProjectID))
	sb.WriteString(fmt.Sprintf("FULLSEND_GCP_WIF_PROVIDER=%s\n", result.WIFProvider))
	sb.WriteString(fmt.Sprintf("FULLSEND_GCP_REGION=%s\n", result.Region))
	return sb.String()
}
