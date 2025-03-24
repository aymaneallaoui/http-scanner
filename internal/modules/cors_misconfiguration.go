package modules

import (
	"fmt"
	"strings"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type CORSMisconfigurationModule struct{}

func (m *CORSMisconfigurationModule) Name() string {
	return "CORSMisconfiguration"
}

func (m *CORSMisconfigurationModule) Description() string {
	return "Checks for Cross-Origin Resource Sharing (CORS) misconfigurations"
}

func (m *CORSMisconfigurationModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()
	target := s.GetTarget()

	headers := map[string]string{
		"Origin": "https://malicious-site.com",
	}

	logger.Debug("Testing for CORS misconfiguration")
	resp, err := s.SendHTTPRequest("GET", "/", headers, nil)
	if err != nil {
		logger.Errorf("Error requesting with modified Origin: %v", err)
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "https://malicious-site.com" && acac == "true" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CORS-01",
			Name:        "CORS Misconfiguration - Origin Reflection with Credentials",
			Description: "The application reflects arbitrary origins in CORS headers with credentials allowed",
			Severity:    model.SeverityHigh,
			CVSS:        8.0,
			Detail:      "The application reflects the Origin header in the Access-Control-Allow-Origin header and allows credentials",
			Evidence:    fmt.Sprintf("Origin: %s, ACAO: %s, ACAC: %s", "https://malicious-site.com", acao, acac),
			Remediation: "Implement a whitelist-based approach for the Access-Control-Allow-Origin header, or avoid setting Access-Control-Allow-Credentials to true",
			Reference:   "https://portswigger.net/web-security/cors",
		})
	} else if acao == "https://malicious-site.com" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CORS-02",
			Name:        "CORS Misconfiguration - Origin Reflection",
			Description: "The application reflects arbitrary origins in CORS headers",
			Severity:    model.SeverityMedium,
			CVSS:        5.3,
			Detail:      "The application reflects the Origin header in the Access-Control-Allow-Origin header",
			Evidence:    fmt.Sprintf("Origin: %s, ACAO: %s", "https://malicious-site.com", acao),
			Remediation: "Implement a whitelist-based approach for the Access-Control-Allow-Origin header",
			Reference:   "https://portswigger.net/web-security/cors",
		})
	} else if acao == "*" && acac == "true" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CORS-03",
			Name:        "CORS Misconfiguration - Wildcard Origin with Credentials",
			Description: "The application uses a wildcard origin with credentials allowed",
			Severity:    model.SeverityHigh,
			CVSS:        7.5,
			Detail:      "The application uses a wildcard in the Access-Control-Allow-Origin header and allows credentials",
			Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
			Remediation: "Avoid using a wildcard in the Access-Control-Allow-Origin header when credentials are allowed",
			Reference:   "https://portswigger.net/web-security/cors",
		})
	}

	headers = map[string]string{
		"Origin": "null",
	}

	resp, err = s.SendHTTPRequest("GET", "/", headers, nil)
	if err != nil {
		logger.Debugf("Error requesting with null Origin: %v", err)
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	acao = resp.Header.Get("Access-Control-Allow-Origin")
	acac = resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "null" && acac == "true" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "CORS-04",
			Name:        "CORS Misconfiguration - Null Origin with Credentials",
			Description: "The application allows the null origin in CORS headers with credentials allowed",
			Severity:    model.SeverityHigh,
			CVSS:        7.2,
			Detail:      "The application allows the null origin and credentials, which can be exploited through sandboxed iframes",
			Evidence:    fmt.Sprintf("Origin: null, ACAO: %s, ACAC: %s", acao, acac),
			Remediation: "Avoid allowing the null origin in your CORS policy, especially with credentials",
			Reference:   "https://portswigger.net/web-security/cors",
		})
	}

	hostname := target.Hostname
	parts := strings.Split(hostname, ".")
	if len(parts) > 2 {
		subdomain := "evil-subdomain." + strings.Join(parts[len(parts)-2:], ".")

		headers = map[string]string{
			"Origin": "https://" + subdomain,
		}

		resp, err = s.SendHTTPRequest("GET", "/", headers, nil)
		if err != nil {
			logger.Debugf("Error requesting with subdomain Origin: %v", err)
			return vulnerabilities, nil
		}
		defer resp.Body.Close()

		acao = resp.Header.Get("Access-Control-Allow-Origin")
		acac = resp.Header.Get("Access-Control-Allow-Credentials")

		if strings.Contains(acao, subdomain) && acac == "true" {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "CORS-05",
				Name:        "CORS Misconfiguration - Trusted Subdomains with Credentials",
				Description: "The application trusts all subdomains in CORS policy with credentials allowed",
				Severity:    model.SeverityMedium,
				CVSS:        6.5,
				Detail:      "The application allows subdomains in the CORS policy with credentials, which can be exploited if a subdomain is vulnerable",
				Evidence:    fmt.Sprintf("Origin: https://%s, ACAO: %s, ACAC: %s", subdomain, acao, acac),
				Remediation: "Avoid trusting all subdomains in your CORS policy when credentials are allowed",
				Reference:   "https://portswigger.net/web-security/cors",
			})
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&CORSMisconfigurationModule{})
}
