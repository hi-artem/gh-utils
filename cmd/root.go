/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"

	"main/utils"

	"github.com/spf13/cobra"
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
		utils.GetFileDiffs(organization, repository, commit)
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
