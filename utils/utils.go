package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/go-github/v48/github"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type fileDiffs struct {
	Results []string `json:"results"`
}

func GetFileDiffs(o, r, c string) {
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

	opt := &github.ListOptions{
		PerPage: 20,
	}

	var allFiles []*github.CommitFile

	for {
		files, resp, err := client.PullRequests.ListFiles(ctx, o, r, *pulls[0].Number, opt)

		if err != nil {
			panic(err)
		}
		allFiles = append(allFiles, files...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	var changedDirs []string
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
	jsondat := &fileDiffs{Results: changedDirs}
	encjson, _ := json.Marshal(jsondat)
	fmt.Println(string(encjson))
}
