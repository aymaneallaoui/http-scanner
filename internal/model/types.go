package model

const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

type Vulnerability struct {
	ID          string  `json:"id" yaml:"id"`
	Name        string  `json:"name" yaml:"name"`
	Description string  `json:"description" yaml:"description"`
	Severity    string  `json:"severity" yaml:"severity"`
	CVSS        float64 `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	CVE         string  `json:"cve,omitempty" yaml:"cve,omitempty"`
	Detail      string  `json:"detail,omitempty" yaml:"detail,omitempty"`
	Evidence    string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string  `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Reference   string  `json:"reference,omitempty" yaml:"reference,omitempty"`
}

type ScanResult struct {
	Target          string          `json:"target" yaml:"target"`
	Timestamp       string          `json:"timestamp" yaml:"timestamp"`
	Duration        string          `json:"duration" yaml:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" yaml:"vulnerabilities"`
	Stats           struct {
		Critical int `json:"critical" yaml:"critical"`
		High     int `json:"high" yaml:"high"`
		Medium   int `json:"medium" yaml:"medium"`
		Low      int `json:"low" yaml:"low"`
		Info     int `json:"info" yaml:"info"`
		Total    int `json:"total" yaml:"total"`
	} `json:"stats" yaml:"stats"`
}

type Target struct {
	URL      string
	Hostname string
	Port     string
	SSL      bool
	Path     string
	Headers  map[string]string
}
