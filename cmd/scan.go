package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/core"
	_ "github.com/aymaneallaoui/kafka-http-scanner/internal/modules"
	"github.com/aymaneallaoui/kafka-http-scanner/internal/output"
	"github.com/aymaneallaoui/kafka-http-scanner/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	targetURL     string
	outputFile    string
	outputFormat  string
	concurrency   int
	timeout       int
	retries       int
	skipSSLVerify bool
	enableModule  string
	disableModule string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target for vulnerabilities",
	Long:  `Scan a target URL for HTTP security vulnerabilities.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if targetURL == "" {
			logger.Fatal("Target URL is required")
			return nil
		}

		if !silent {
			printBanner()
		}

		config := core.Config{
			Timeout:         timeout,
			MaxRetries:      retries,
			Concurrency:     concurrency,
			FollowRedirects: true,
			SkipSSLVerify:   skipSSLVerify,
			OutputFormat:    outputFormat,
		}

		if enableModule != "" {
			config.EnabledModules = parseCommaSeparatedList(enableModule)
		}

		if disableModule != "" {
			config.DisabledModules = parseCommaSeparatedList(disableModule)
		}

		scanner, err := core.NewScanner(config, logger)
		if err != nil {
			logger.Fatalf("Error initializing scanner: %v", err)
			return err
		}

		target, err := utils.ParseURL(targetURL)
		if err != nil {
			logger.Fatalf("Error parsing URL: %v", err)
			return err
		}
		scanner.SetTarget(target)

		if !silent {
			logger.Infof("Target: %s", scanner.GetTarget().URL)
			logger.Infof("Started scan at: %s", time.Now().Format(time.RFC3339))
			logger.Info("========================================================")
		}

		startTime := time.Now()
		if err := scanner.RunScan(); err != nil {
			logger.Fatalf("Error during scan: %v", err)
			return err
		}

		result := scanner.GetResults()
		result.Timestamp = startTime.Format(time.RFC3339)
		result.Duration = time.Since(startTime).String()
		result.Target = scanner.GetTarget().URL

		if !silent {
			output.PrintResults(result, os.Stdout)
		}

		if outputFile != "" {
			if err := output.SaveResults(result, outputFile, outputFormat); err != nil {
				logger.Errorf("Error saving results: %v", err)
				return err
			} else if !silent {
				logger.Infof("Results saved to: %s", outputFile)
			}
		}

		if result.Stats.Total > 0 {
			if !silent {
				logger.Errorf("Found %d vulnerabilities", result.Stats.Total)
			}
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&targetURL, "url", "", "Target URL (e.g., https://example.com)")
	scanCmd.Flags().StringVar(&outputFile, "output", "", "Output file for results")
	scanCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format (text, json, yaml)")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent tests")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "Connection timeout in seconds")
	scanCmd.Flags().IntVar(&retries, "retries", 3, "Number of retries for failed requests")
	scanCmd.Flags().BoolVar(&skipSSLVerify, "skip-ssl-verify", false, "Skip SSL certificate verification")
	scanCmd.Flags().StringVar(&enableModule, "enable", "", "Enable specific modules (comma-separated)")
	scanCmd.Flags().StringVar(&disableModule, "disable", "", "Disable specific modules (comma-separated)")
}

func parseCommaSeparatedList(input string) []string {
	if input == "" {
		return nil
	}
	return strings.Split(input, ",")
}

func printBanner() {
	red := "\033[31m"
	reset := "\033[0m"

	banner := `

	/$$$$$$            /$$   /$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$   /$$$$$$                                                             
	/$$__  $$          | $$  | $$|__  $$__/|__  $$__/| $$__  $$ /$$__  $$                                                            
   | $$  \__/  /$$$$$$ | $$  | $$   | $$      | $$   | $$  \ $$| $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
   | $$ /$$$$ /$$__  $$| $$$$$$$$   | $$      | $$   | $$$$$$$/|  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
   | $$|_  $$| $$  \ $$| $$__  $$   | $$      | $$   | $$____/  \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
   | $$  \ $$| $$  | $$| $$  | $$   | $$      | $$   | $$       /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
   |  $$$$$$/|  $$$$$$/| $$  | $$   | $$      | $$   | $$      |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
	\______/  \______/ |__/  |__/   |__/      |__/   |__/       \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/         
                                                                                          
`
	fmt.Println(red + banner + reset)
	fmt.Printf("%sGoHTTPScanner v%s - Advanced HTTP Security Vulnerability Scanner%s\n", red, version, reset)
	fmt.Println(red + "==========================================================" + reset)
}
