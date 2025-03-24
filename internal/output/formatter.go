package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
	"gopkg.in/yaml.v3"
)

type Formatter interface {
	Format(result model.ScanResult, w io.Writer) error
}

type TextFormatter struct{}

type JSONFormatter struct {
	Indent bool
}

type YAMLFormatter struct{}

func (f *TextFormatter) Format(result model.ScanResult, w io.Writer) error {
	fmt.Fprintln(w, "\nScan Results:")
	fmt.Fprintln(w, "=============")
	fmt.Fprintf(w, "Target: %s\n", result.Target)
	fmt.Fprintf(w, "Scan Duration: %s\n", result.Duration)
	fmt.Fprintf(w, "Total Vulnerabilities: %d\n", result.Stats.Total)
	fmt.Fprintf(w, "  Critical: %d\n", result.Stats.Critical)
	fmt.Fprintf(w, "  High: %d\n", result.Stats.High)
	fmt.Fprintf(w, "  Medium: %d\n", result.Stats.Medium)
	fmt.Fprintf(w, "  Low: %d\n", result.Stats.Low)
	fmt.Fprintf(w, "  Info: %d\n", result.Stats.Info)
	fmt.Fprintln(w, "\nDetailed Findings:")
	fmt.Fprintln(w, "=================")

	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found.")
		return nil
	}

	severities := []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	for _, severity := range severities {
		var vulnsOfSeverity []model.Vulnerability
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == severity {
				vulnsOfSeverity = append(vulnsOfSeverity, vuln)
			}
		}

		if len(vulnsOfSeverity) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n[%s] Severity Vulnerabilities:\n", severity)
		fmt.Fprintln(w, "----------------------------------------")

		for i, vuln := range vulnsOfSeverity {
			fmt.Fprintf(w, "%d. %s", i+1, vuln.Name)
			if vuln.ID != "" {
				fmt.Fprintf(w, " [%s]", vuln.ID)
			}
			fmt.Fprintln(w)

			if vuln.Description != "" {
				fmt.Fprintf(w, "   Description: %s\n", vuln.Description)
			}
			if vuln.Detail != "" {
				fmt.Fprintf(w, "   Details: %s\n", vuln.Detail)
			}
			if vuln.Evidence != "" {
				fmt.Fprintf(w, "   Evidence: %s\n", vuln.Evidence)
			}
			if vuln.Remediation != "" {
				fmt.Fprintf(w, "   Remediation: %s\n", vuln.Remediation)
			}
			fmt.Fprintln(w)
		}
	}

	return nil
}

func (f *JSONFormatter) Format(result model.ScanResult, w io.Writer) error {
	var data []byte
	var err error

	if f.Indent {
		data, err = json.MarshalIndent(result, "", "  ")
	} else {
		data, err = json.Marshal(result)
	}

	if err != nil {
		return fmt.Errorf("error marshaling results to JSON: %v", err)
	}

	_, err = w.Write(data)
	return err
}

func (f *YAMLFormatter) Format(result model.ScanResult, w io.Writer) error {
	data, err := yaml.Marshal(result)
	if err != nil {
		return fmt.Errorf("error marshaling results to YAML: %v", err)
	}

	_, err = w.Write(data)
	return err
}

func GetFormatter(format string, indent bool) Formatter {
	switch format {
	case "json":
		return &JSONFormatter{Indent: indent}
	case "yaml":
		return &YAMLFormatter{}
	default:
		return &TextFormatter{}
	}
}
