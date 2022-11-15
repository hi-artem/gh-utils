package utils

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	ghcommenter "github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/github"

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

func GetPRNumber(ctx *context.Context) {
	localCtx := *ctx
	o := localCtx.Value("ghOrganization")
	r := localCtx.Value("ghRepository")
	c := localCtx.Value("ghCommit")

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(*ctx, ts)

	client := github.NewClient(tc)

	pulls, _, err := client.PullRequests.ListPullRequestsWithCommit(context.TODO(), o.(string), r.(string), c.(string), nil)

	if err != nil {
		panic(err)
	}

	if len(pulls) != 1 {
		panic("Can not find pull request")
	}

	fmt.Println("Found PR", *pulls[0].Number)

	*ctx = context.WithValue(*ctx, "ghPR", *pulls[0].Number)
}

func GetFileDiffs(ctx *context.Context) []string {
	localCtx := *ctx
	o := localCtx.Value("ghOrganization")
	r := localCtx.Value("ghRepository")
	pr := localCtx.Value("ghPR")

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(*ctx, ts)

	client := github.NewClient(tc)

	var allFiles []*github.CommitFile
	opt := &github.ListOptions{
		PerPage: 20,
	}

	for {
		files, resp, err := client.PullRequests.ListFiles(context.TODO(), o.(string), r.(string), pr.(int), opt)

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

func GitClone(ctx *context.Context) {
	localCtx := *ctx
	o := localCtx.Value("ghOrganization")
	r := localCtx.Value("ghRepository")
	c := localCtx.Value("ghCommit")
	repoDir := localCtx.Value("repositoryDirectory")

	ghUrl := fmt.Sprintf("https://github.com/%s/%s", o, r)

	fmt.Println("git clone", ghUrl)
	repo, err := git.PlainClone(repoDir.(string), false, &git.CloneOptions{
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
		Hash: plumbing.NewHash(c.(string)),
	})

	if err != nil {
		panic(err)
	}
}

func GetAtlantisProjects(ctx *context.Context) []string {
	localCtx := *ctx
	repoDir := localCtx.Value("repositoryDirectory")

	var globalCfgArgs = valid.GlobalCfgArgs{
		AllowRepoCfg:  true,
		MergeableReq:  false,
		ApprovedReq:   false,
		UnDivergedReq: false,
	}
	var globalCfg = valid.NewGlobalCfgFromArgs(globalCfgArgs)

	parserValidator := config.ParserValidator{}
	repoCfg, err := parserValidator.ParseRepoCfg(repoDir.(string), globalCfg, "")

	if err != nil {
		panic(err)
	}
	var allFiles []string

	for _, p := range repoCfg.Projects {
		allFiles = append(allFiles, p.Dir)
	}
	return allFiles
}

func RunCommenter(ctx *context.Context, reportLocation string) {
	localCtx := *ctx
	o := localCtx.Value("ghOrganization")
	r := localCtx.Value("ghRepository")
	pr := localCtx.Value("ghPR")
	repoDir := localCtx.Value("repositoryDirectory")

	loadedReport, err := loadReportFile(reportLocation)
	if err != nil {
		panic(err)
	}
	repo, err := ghcommenter.NewGithub(os.Getenv("GITHUB_TOKEN"), o.(string), r.(string), pr.(int))
	if err != nil {
		panic(err)
	}
	c := commenter.Repository(repo)

	var errMessages []string

	for _, reportItem := range loadedReport {
		reportItem.Range.Filename = reportItem.Range.Filename
		comment := generateErrorMessage(reportItem)
		fmt.Printf("Preparing comment for violation of rule %v in %v\n", reportItem.RuleID, reportItem.Range.Filename)
		err := c.WriteMultiLineComment(strings.ReplaceAll(reportItem.Range.Filename, repoDir.(string)+"/", ""), comment, reportItem.Range.StartLine, reportItem.Range.EndLine)
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
