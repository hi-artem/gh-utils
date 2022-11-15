package utils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/extrafs"
	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"

	"github.com/aquasecurity/tfsec/version"
)

func RunScan(path string) string {
	var scannerOptions []options.ScannerOption
	scannerOptions = append(
		scannerOptions,
		scanner.ScannerWithSingleThread(false),
		scanner.ScannerWithStopOnHCLError(false),
		scanner.ScannerWithStopOnRuleErrors(false),
		scanner.ScannerWithSkipDownloaded(false),
		scanner.ScannerWithAllDirectories(false),
		// scanner.ScannerWithWorkspaceName("default"),
		// scanner.ScannerWithAlternativeIDProvider(legacy.FindIDs),
		// options.ScannerWithPolicyNamespaces("custom"),
		scanner.ScannerWithDownloadsAllowed(true),
		options.ScannerWithRegoOnly(false),
		options.ScannerWithEmbeddedPolicies(true),
	)

	scnr := scanner.New(scannerOptions...)

	dir, err := findDirectory(path)
	if err != nil {
		panic(err)
	}

	fmt.Println("Determined working directory=%s", dir)

	root, rel, err := splitRoot(dir)

	if err != nil {
		panic(err)
	}
	fmt.Println("Determined path root=%s", root)
	fmt.Println("Determined path rel=%s", rel)

	results, _, err := scnr.ScanFSWithMetrics(context.TODO(), extrafs.OSDir(root), rel)
	if err != nil {
		panic(err)
	}

	factory := formatters.New().
		WithDebugEnabled(false).
		WithColoursEnabled(false).
		WithGroupingEnabled(true).
		WithLinksFunc(gatherLinks).
		WithFSRoot(root).
		WithBaseDir(rel).
		WithMetricsEnabled(false).
		WithIncludeIgnored(true).
		WithIncludePassed(false).
		WithRelativePaths(false).
		AsJSON()

	outputPath := dir + "/results.json"
	fmt.Println("Saving scan to outputPath=%s", outputPath)

	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	factory.WithWriter(f)
	fmt.Println("Saved scan to outputPath=%s", outputPath)
	factory.Build().Output(results)

	return outputPath
}

func gatherLinks(result scan.Result) []string {
	v := "latest"
	if version.Version != "" {
		v = version.Version
	}
	var links []string
	if result.Rule().Terraform != nil {
		links = result.Rule().Terraform.Links
	}

	var docsLink []string
	if result.Rule().Provider == providers.CustomProvider {
		docsLink = result.Rule().Links
	} else {
		docsLink = []string{
			fmt.Sprintf(
				"https://aquasecurity.github.io/tfsec/%s/checks/%s/%s/%s/",
				v,
				result.Rule().Provider,
				strings.ToLower(result.Rule().Service),
				result.Rule().ShortCode,
			),
		}
	}

	return append(docsLink, links...)
}

func findDirectory(p string) (string, error) {
	dir, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("could not determine absolute path for provided path: %w", err)
	}

	if dirInfo, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("failed to access provided path: %w", err)
	} else if !dirInfo.IsDir() {
		return "", fmt.Errorf("provided path is not a dir")
	}

	return dir, nil
}

func splitRoot(dir string) (string, string, error) {
	root := "/"
	var rel string
	if vol := filepath.VolumeName(dir); vol != "" {
		root = vol
		if len(dir) <= len(vol)+1 {
			rel = "."
		} else {
			rel = dir[len(vol)+1:]
		}
	} else {
		var err error
		rel, err = filepath.Rel(root, dir)
		if err != nil {
			return "", "", fmt.Errorf("failed to set relative path: %w", err)
		}
	}
	return root, rel, nil
}
