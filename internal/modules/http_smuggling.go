package modules

import (
	"strings"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type HTTPSmugglingModule struct{}

func (m *HTTPSmugglingModule) Name() string {
	return "HttpSmuggling"
}

func (m *HTTPSmugglingModule) Description() string {
	return "Detects HTTP request smuggling vulnerabilities"
}

func (m *HTTPSmugglingModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	target := s.GetTarget()
	logger := s.GetLogger()

	payload := "POST / HTTP/1.1\r\n" +
		"Host: " + target.Hostname + "\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"X"

	logger.Debug("Testing for CL.TE vulnerability")
	response, err := s.SendRawRequest(payload)
	if err == nil {
		if !strings.Contains(response, "400 Bad Request") &&
			!strings.Contains(response, "501 Not Implemented") &&
			(strings.Contains(response, "200 OK") || response == "") {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "HTTP-SMUGGLE-01",
				Name:        "HTTP Request Smuggling (CL.TE)",
				Description: "The server is vulnerable to HTTP request smuggling using Content-Length and Transfer-Encoding headers",
				Severity:    model.SeverityHigh,
				CVSS:        8.1,
				Detail:      "The server appears to process both Content-Length and Transfer-Encoding headers, which can lead to request smuggling attacks.",
				Evidence:    "Server accepted malformed request with conflicting headers",
				Remediation: "Configure the server to reject requests with both Content-Length and Transfer-Encoding headers or ensure consistent handling.",
				Reference:   "https://portswigger.net/web-security/request-smuggling",
			})
		}
	}

	payload = "POST / HTTP/1.1\r\n" +
		"Host: " + target.Hostname + "\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"12\r\n" +
		"smuggled request\r\n" +
		"0\r\n" +
		"\r\n"

	logger.Debug("Testing for TE.CL vulnerability")
	response, err = s.SendRawRequest(payload)
	if err == nil {
		if !strings.Contains(response, "400 Bad Request") &&
			(strings.Contains(response, "200 OK") || response == "") {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "HTTP-SMUGGLE-02",
				Name:        "HTTP Request Smuggling (TE.CL)",
				Description: "The server is vulnerable to HTTP request smuggling using Transfer-Encoding and Content-Length headers",
				Severity:    model.SeverityHigh,
				CVSS:        8.1,
				Detail:      "The server appears to process Transfer-Encoding over Content-Length, which can lead to request smuggling attacks.",
				Evidence:    "Server accepted malformed request with conflicting headers",
				Remediation: "Configure the server to reject requests with both Content-Length and Transfer-Encoding headers or ensure consistent handling.",
				Reference:   "https://portswigger.net/web-security/request-smuggling",
			})
		}
	}

	payload = "POST / HTTP/1.1\r\n" +
		"Host: " + target.Hostname + "\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Transfer-Encoding: identity\r\n" +
		"\r\n" +
		"12\r\n" +
		"smuggled request\r\n" +
		"0\r\n" +
		"\r\n"

	logger.Debug("Testing for TE.TE vulnerability")
	response, err = s.SendRawRequest(payload)
	if err == nil {
		if !strings.Contains(response, "400 Bad Request") &&
			(strings.Contains(response, "200 OK") || response == "") {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "HTTP-SMUGGLE-03",
				Name:        "HTTP Request Smuggling (TE.TE)",
				Description: "The server is vulnerable to HTTP request smuggling using multiple Transfer-Encoding headers",
				Severity:    model.SeverityHigh,
				CVSS:        8.1,
				Detail:      "The server processes multiple Transfer-Encoding headers inconsistently, which can lead to request smuggling attacks.",
				Evidence:    "Server accepted malformed request with multiple Transfer-Encoding headers",
				Remediation: "Configure the server to reject requests with multiple Transfer-Encoding headers or ensure consistent handling.",
				Reference:   "https://portswigger.net/web-security/request-smuggling",
			})
		}
	}

	payload = "POST / HTTP/1.1\r\n" +
		"Host: " + target.Hostname + "\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chu\r\nked\r\n" +
		"\r\n" +
		"12\r\n" +
		"smuggled request\r\n" +
		"0\r\n" +
		"\r\n"

	logger.Debug("Testing for obfuscated TE header vulnerability")
	response, err = s.SendRawRequest(payload)
	if err == nil {
		if !strings.Contains(response, "400 Bad Request") &&
			(strings.Contains(response, "200 OK") || response == "") {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "HTTP-SMUGGLE-04",
				Name:        "HTTP Request Smuggling (Obfuscated TE)",
				Description: "The server is vulnerable to HTTP request smuggling using obfuscated Transfer-Encoding headers",
				Severity:    model.SeverityHigh,
				CVSS:        8.1,
				Detail:      "The server processes obfuscated Transfer-Encoding headers, which can lead to request smuggling attacks.",
				Evidence:    "Server accepted malformed request with obfuscated Transfer-Encoding header",
				Remediation: "Configure the server to properly validate Transfer-Encoding headers and reject malformed ones.",
				Reference:   "https://portswigger.net/web-security/request-smuggling",
			})
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&HTTPSmugglingModule{})
}
