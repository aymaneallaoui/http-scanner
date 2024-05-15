package cmd

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	configFile string
	verbose    bool
	silent     bool
	logger     *logrus.Logger
)

var RootCmd = &cobra.Command{
	Use:   "gohttpscanner",
	Short: "An advanced HTTP security vulnerability scanner",
	Long: `GoHTTPSecScanner is an advanced HTTP security vulnerability scanner that 
detects a wide range of web application vulnerabilities including HTTP smuggling,
XSS, SQL injection, and many other vulnerabilities.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger = logrus.New()

		if silent {
			logger.SetOutput(os.NewFile(0, os.DevNull))
		}

		if verbose {
			logger.SetLevel(logrus.DebugLevel)
		} else {
			logger.SetLevel(logrus.InfoLevel)
		}

		if !isTerminal() {
			logger.SetFormatter(&logrus.JSONFormatter{})
		} else {
			logger.SetFormatter(&logrus.TextFormatter{
				ForceColors:     true,
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			})
		}
	},
}

func init() {
	RootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file (default is ./configs/default.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	RootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Silence all output")

	RootCmd.AddCommand(scanCmd)
	RootCmd.AddCommand(versionCmd)
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
