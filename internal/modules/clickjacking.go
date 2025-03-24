package modules

import (
	"strings"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type ClickjackingModule struct{}

func (m *ClickjackingModule) Name() string {
	return "Clickjacking"
}

func (m *ClickjackingModule) Description() string {
	return "Checks for clickjacking vulnerabilities"
}

func (m *ClickjackingModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()

	logger.Debug("Testing for clickjacking vulnerabilities")
	resp, err := s.SendHTTPRequest("GET", "/", nil, nil)
	if err != nil {
		logger.Errorf("Error in Clickjacking module: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	xFrameOptions := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	if xFrameOptions == "" {
		if !strings.Contains(csp, "frame-ancestors") {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "CLICKJACK-01",
				Name:        "Clickjacking Vulnerability",
				Description: "The application is vulnerable to clickjacking attacks",
				Severity:    model.SeverityMedium,
				CVSS:        6.5,
				Detail:      "The application does not set X-Frame-Options or CSP frame-ancestors directive",
				Remediation: "Set X-Frame-Options header to DENY or SAMEORIGIN, or use CSP frame-ancestors directive",
				Reference:   "https://owasp.org/www-community/attacks/Clickjacking",
			})
		}
	} else if xFrameOptions != "DENY" && xFrameOptions != "SAMEORIGIN" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CLICKJACK-02",
			Name:        "Weak X-Frame-Options Configuration",
			Description: "The application has a weak X-Frame-Options configuration",
			Severity:    model.SeverityLow,
			CVSS:        4.3,
			Detail:      "The application uses an invalid or weak X-Frame-Options value: " + xFrameOptions,
			Remediation: "Set X-Frame-Options header to DENY or SAMEORIGIN",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		})
	}

	if strings.Contains(csp, "frame-ancestors") {
		if !strings.Contains(csp, "frame-ancestors 'none'") && !strings.Contains(csp, "frame-ancestors 'self'") {
			if strings.Contains(csp, "frame-ancestors *") {
				vulnerabilities = append(vulnerabilities, model.Vulnerability{
					ID:          "CLICKJACK-03",
					Name:        "Weak CSP frame-ancestors Configuration",
					Description: "The application has a weak CSP frame-ancestors configuration",
					Severity:    model.SeverityMedium,
					CVSS:        5.8,
					Detail:      "The application uses a permissive frame-ancestors directive in CSP",
					Remediation: "Set frame-ancestors directive to 'none' or 'self'",
					Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
				})
			}
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&ClickjackingModule{})
}
