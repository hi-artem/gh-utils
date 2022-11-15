package utils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/pkg/extrafs"
	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	ghcommenter "github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/github"

	"github.com/aquasecurity/tfsec/version"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v48/github"
	"github.com/runatlantis/atlantis/server/core/config"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type fileDiffs struct {
	Results []string `json:"results"`
}

func GetPRNumber(o, r, c string) int {
	ctx := context.Background()

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	pulls, _, err := client.PullRequests.ListPullRequestsWithCommit(ctx, o, r, c, nil)

	if err != nil {
		panic(err)
	}

	if len(pulls) != 1 {
		panic("Can not find pull request")
	}

	fmt.Println("Found PR", *pulls[0].Number)

	return *pulls[0].Number
}

func GetFileDiffs(o string, r string, pr int) []string {
	ctx := context.Background()

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	var allFiles []*github.CommitFile
	opt := &github.ListOptions{
		PerPage: 20,
	}

	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, o, r, pr, opt)

		if err != nil {
			panic(err)
		}
		allFiles = append(allFiles, files...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	changedDirs := []string{}
	dirRegexp, err := regexp.Compile("terraform*")

	if err != nil {
		panic(err)
	}

	for _, x := range allFiles {
		filenameArray := strings.Split(*x.Filename, "/")
		dirName := strings.Join(filenameArray[:len(filenameArray)-1], "/")

		fmt.Println("Found directory", dirName)

		if dirRegexp.MatchString(dirName) && !slices.Contains(changedDirs, dirName) {
			fmt.Println("Adding directory to results", dirName)
			changedDirs = append(changedDirs, dirName)
		} else {
			fmt.Println("Skipping directory", dirName)
		}
	}
	return changedDirs
}

func GitClone(o, r, c string) {
	ghUrl := fmt.Sprintf("https://github.com/%s/%s", o, r)

	fmt.Println("git clone", ghUrl)
	repo, err := git.PlainClone("./"+r, false, &git.CloneOptions{
		URL:      ghUrl,
		Progress: os.Stdout,
		Auth: &http.BasicAuth{
			Username: "anything", // this can be anything except an empty string
			Password: os.Getenv("GITHUB_TOKEN"),
		},
	})

	if err != nil {
		panic(err)
	}

	w, err := repo.Worktree()

	if err != nil {
		panic(err)
	}

	fmt.Println("git checkout", c)
	err = w.Checkout(&git.CheckoutOptions{
		Hash: plumbing.NewHash(c),
	})

	if err != nil {
		panic(err)
	}

}

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

func GetAtlantisProjects(d string) []string {
	var globalCfgArgs = valid.GlobalCfgArgs{
		AllowRepoCfg:  true,
		MergeableReq:  false,
		ApprovedReq:   false,
		UnDivergedReq: false,
	}
	var globalCfg = valid.NewGlobalCfgFromArgs(globalCfgArgs)

	parserValidator := config.ParserValidator{}
	repoCfg, err := parserValidator.ParseRepoCfg(d, globalCfg, "")

	if err != nil {
		panic(err)
	}
	var allFiles []string

	for _, p := range repoCfg.Projects {
		allFiles = append(allFiles, p.Dir)
	}
	return allFiles
}

func RunCommenter(reportLocation string, o string, r string, pr int) {
	loadedReport, err := loadReportFile(reportLocation)
	if err != nil {
		panic(err)
	}
	repo, err := ghcommenter.NewGithub(os.Getenv("GITHUB_TOKEN"), o, r, pr)
	if err != nil {
		panic(err)
	}
	c := commenter.Repository(repo)

	var errMessages []string

	for _, reportItem := range loadedReport {
		reportItem.Range.Filename = reportItem.Range.Filename
		comment := generateErrorMessage(reportItem)
		fmt.Printf("Preparing comment for violation of rule %v in %v\n", reportItem.RuleID, reportItem.Range.Filename)
		err := c.WriteMultiLineComment(strings.ReplaceAll(reportItem.Range.Filename, "/Users/aakatev/Documents/work/gh-utils/fake-terraform/", ""), comment, reportItem.Range.StartLine, reportItem.Range.EndLine)
		if err != nil {
			// don't error if its simply that the comments aren't valid for the PR
			switch err.(type) {
			case ghcommenter.CommentAlreadyWrittenError:
				fmt.Println("Ignoring - comment already written")
			case ghcommenter.CommentNotValidError:
				fmt.Println("Ignoring - change not part of the current PR")
				continue
			default:
				errMessages = append(errMessages, err.Error())
			}
		} else {
			fmt.Printf("Commenting for %s to %s:%d:%d\n", reportItem.Description, reportItem.Range.Filename, reportItem.Range.StartLine, reportItem.Range.EndLine)
		}
		if len(errMessages) > 0 {
			fmt.Printf("There were %d errors:\n", len(errMessages))
			for _, err := range errMessages {
				fmt.Println(err)
			}
			os.Exit(1)
		}
	}
}

func generateErrorMessage(r ReportItem) string {
	return fmt.Sprintf(`:warning: tfsec found a **%s** severity issue from rule `+"`%s`"+`:
> %s
More information available %s`,
		r.Severity, r.RuleID, r.Description, formatUrls(r.Links))
}

func formatUrls(urls []string) string {
	urlList := ""
	for _, url := range urls {
		if urlList != "" {
			urlList += fmt.Sprintf(" and ")
		}
		urlList += fmt.Sprintf("[here](%s)", url)
	}
	return urlList
}
