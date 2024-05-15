package modules

import (
	"fmt"
	"strings"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
)

type ContentSecurityModule struct{}

func (m *ContentSecurityModule) Name() string {
	return "ContentSecurity"
}

func (m *ContentSecurityModule) Description() string {
	return "Checks for content security issues like MIME type confusion"
}

func (m *ContentSecurityModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()

	resp, err := s.SendHTTPRequest("GET", "", nil, nil)
	if err != nil {
		logger.Errorf("Error in ContentSecurity module: %v", err)
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CONTENT-01",
			Name:        "Missing Content-Type Header",
			Description: "The server does not specify a Content-Type header",
			Severity:    model.SeverityLow,
			CVSS:        3.7,
			Detail:      "Missing Content-Type headers may lead to MIME type confusion",
			Remediation: "Configure the server to always send appropriate Content-Type headers",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type",
		})
	}

	headers := map[string]string{
		"Accept": "*/*",
	}

	resp, err = s.SendHTTPRequest("GET", "/non-existent-file.txt.html", headers, nil)
	if err == nil {
		defer resp.Body.Close()
		contentType = resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") && resp.StatusCode != 404 {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "CONTENT-02",
				Name:        "MIME Type Confusion Possible",
				Description: "The server may be vulnerable to MIME type confusion attacks",
				Severity:    model.SeverityLow,
				CVSS:        4.3,
				Detail:      "The server appears to determine content type based on file extension or content instead of proper MIME type handling",
				Remediation: "Configure the server to use proper MIME type handling and set X-Content-Type-Options: nosniff",
				Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
			})
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&ContentSecurityModule{})
}
