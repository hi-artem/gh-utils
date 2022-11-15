/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"context"
	"fmt"
	"main/utils"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "main",
	Short: "GitHub Utils",
	Long: `GitHub Utils

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		organization, _ := cmd.Flags().GetString("organization")
		repository, _ := cmd.Flags().GetString("repository")
		commit, _ := cmd.Flags().GetString("commit")

		ctx := context.Background()
		ctx = context.WithValue(ctx, "ghOrganization", organization)
		ctx = context.WithValue(ctx, "ghRepository", repository)
		ctx = context.WithValue(ctx, "ghCommit", commit)

		utils.InitState(&ctx)
		fmt.Println(ctx.Value("repositoryDirectory"))

		utils.GetPRNumber(&ctx)
		diffs := utils.GetFileDiffs(&ctx)

		utils.GitClone(&ctx)

		projects := utils.GetAtlantisProjects(&ctx)
		diffsProjects := []string{}

		for _, d := range diffs {
			if slices.Contains(projects, d) {
				diffsProjects = append(diffsProjects, d)
			}
		}
		fmt.Println(diffsProjects)

		for _, value := range diffsProjects {
			reportFile := utils.RunScan(repository + "/" + value)
			utils.RunCommenter(&ctx, reportFile)
		}

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.main.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	rootCmd.Flags().StringP("organization", "o", "", "GitHub organization or owner")
	rootCmd.Flags().StringP("repository", "r", "", "GitHub repository")
	rootCmd.Flags().StringP("commit", "c", "", "GitHub commit")
	rootCmd.MarkFlagRequired("organization")
	rootCmd.MarkFlagRequired("repository")
	rootCmd.MarkFlagRequired("commit")
}
