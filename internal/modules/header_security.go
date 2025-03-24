package modules

import (
	"fmt"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type HeaderSecurityModule struct{}

func (m *HeaderSecurityModule) Name() string {
	return "HeaderSecurity"
}

func (m *HeaderSecurityModule) Description() string {
	return "Checks for missing or insecure HTTP security headers"
}

func (m *HeaderSecurityModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability

	resp, err := s.SendHTTPRequest("GET", "", nil, nil)
	if err != nil {
		s.GetLogger().Errorf("Error in HeaderSecurity module: %v", err)
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Frame-Options") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-01",
			Name:        "Missing X-Frame-Options Header",
			Description: "The X-Frame-Options header is not set, which may allow clickjacking attacks",
			Severity:    model.SeverityMedium,
			CVSS:        5.8,
			Detail:      "X-Frame-Options header prevents a web page from being displayed in a frame on another domain",
			Remediation: "Add X-Frame-Options header with value DENY or SAMEORIGIN",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		})
	}

	if resp.Header.Get("Content-Security-Policy") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-02",
			Name:        "Missing Content-Security-Policy Header",
			Description: "The Content-Security-Policy header is not set",
			Severity:    model.SeverityMedium,
			CVSS:        6.1,
			Detail:      "Content-Security-Policy helps prevent XSS attacks by specifying which dynamic resources are allowed to load",
			Remediation: "Implement a Content-Security-Policy header with appropriate directives",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
		})
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-03",
			Name:        "Missing X-Content-Type-Options Header",
			Description: "The X-Content-Type-Options header is not set",
			Severity:    model.SeverityLow,
			CVSS:        3.7,
			Detail:      "X-Content-Type-Options prevents MIME type sniffing",
			Remediation: "Add X-Content-Type-Options header with value nosniff",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		})
	}

	if s.GetTarget().SSL && resp.Header.Get("Strict-Transport-Security") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-04",
			Name:        "Missing Strict-Transport-Security Header",
			Description: "The Strict-Transport-Security header is not set",
			Severity:    model.SeverityMedium,
			CVSS:        6.5,
			Detail:      "HSTS ensures that browsers always use HTTPS for communication with the server",
			Remediation: "Add Strict-Transport-Security header with appropriate max-age directive",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		})
	}

	if resp.Header.Get("X-XSS-Protection") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-05",
			Name:        "Missing X-XSS-Protection Header",
			Description: "The X-XSS-Protection header is not set",
			Severity:    model.SeverityLow,
			CVSS:        2.9,
			Detail:      "X-XSS-Protection enables browser's built-in XSS protection",
			Remediation: "Add X-XSS-Protection header with value 1; mode=block",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
		})
	}

	if resp.Header.Get("Referrer-Policy") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-06",
			Name:        "Missing Referrer-Policy Header",
			Description: "The Referrer-Policy header is not set",
			Severity:    model.SeverityLow,
			CVSS:        3.1,
			Detail:      "Referrer-Policy controls how much referrer information is sent with requests",
			Remediation: "Add Referrer-Policy header with appropriate value",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		})
	}

	if resp.Header.Get("Feature-Policy") == "" && resp.Header.Get("Permissions-Policy") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-07",
			Name:        "Missing Permissions-Policy Header",
			Description: "Neither Permissions-Policy nor Feature-Policy header is set",
			Severity:    model.SeverityLow,
			CVSS:        3.3,
			Detail:      "Permissions-Policy allows control over browser features and APIs",
			Remediation: "Add Permissions-Policy header with appropriate directives",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy",
		})
	}

	if resp.Header.Get("Cache-Control") == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "HEADER-08",
			Name:        "Missing Cache-Control Header",
			Description: "The Cache-Control header is not set",
			Severity:    model.SeverityLow,
			CVSS:        3.5,
			Detail:      "Cache-Control directives control caching behavior",
			Remediation: "Add appropriate Cache-Control headers to control caching behavior",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
		})
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&HeaderSecurityModule{})
}
