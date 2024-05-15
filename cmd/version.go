package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	version = "1.0.0"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Long:  `Print the version number of GoHTTPScanner.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("GoHTTPSecScanner v%s\n", version)
	},
}
