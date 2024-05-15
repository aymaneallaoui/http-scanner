package modules

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
)

type ServerInfoLeakageModule struct{}

func (m *ServerInfoLeakageModule) Name() string {
	return "ServerInfoLeakage"
}

func (m *ServerInfoLeakageModule) Description() string {
	return "Checks for server information leakage through headers and error pages"
}

func (m *ServerInfoLeakageModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()

	resp, err := s.SendHTTPRequest("GET", "/", nil, nil)
	if err != nil {
		logger.Errorf("Error in ServerInfoLeakage module: %v", err)
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	if server != "" && !strings.Contains(strings.ToLower(server), "server") {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "INFO-01",
			Name:        "Server Information Disclosure",
			Description: "The server header discloses version information",
			Severity:    model.SeverityLow,
			CVSS:        3.1,
			Detail:      fmt.Sprintf("Server header contains: %s", server),
			Remediation: "Configure the server to provide minimal information in the Server header",
			Reference:   "https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002)",
		})
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "INFO-02",
			Name:        "X-Powered-By Information Disclosure",
			Description: "The X-Powered-By header discloses technology information",
			Severity:    model.SeverityLow,
			CVSS:        3.1,
			Detail:      fmt.Sprintf("X-Powered-By header contains: %s", poweredBy),
			Remediation: "Remove or sanitize the X-Powered-By header",
			Reference:   "https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002)",
		})
	}

	infoHeaders := []string{"X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime"}
	for _, header := range infoHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "INFO-03",
				Name:        "Technology Information Disclosure",
				Description: fmt.Sprintf("The %s header discloses technology information", header),
				Severity:    model.SeverityLow,
				CVSS:        3.1,
				Detail:      fmt.Sprintf("%s header contains: %s", header, value),
				Remediation: fmt.Sprintf("Remove or sanitize the %s header", header),
				Reference:   "https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002)",
			})
		}
	}

	paths := []string{
		"/non-existent-page-" + fmt.Sprintf("%d", time.Now().Unix()),
		"/index.php.bak",
		"/.git/HEAD",
		"/wp-config.php.bak",
		"/config.json",
	}

	for _, path := range paths {
		resp, err := s.SendHTTPRequest("GET", path, nil, nil)
		if err == nil {
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				bodyStr := string(body)

				errorPatterns := []struct {
					pattern string
					name    string
				}{
					{`(?i)Exception|stack trace|System\.Exception|Fatal error|<b>Warning</b>:|^Warning:|[A-Za-z\.]+Exception:`, "Stack Trace Disclosure"},
					{`(?i)SQL syntax.*?error|ORA-[0-9]+|MySQL Query fail|You have an error in your SQL syntax`, "SQL Error Disclosure"},
					{`(?i)Path:.+?\.php|Path:.+?\.asp|Path:.+?\.jsp`, "File Path Disclosure"},
					{`(?i)root:x:|daemon:x:|ftp:x:`, "System File Disclosure"},
					{`(?i)DATABASE_URL|DB_CONNECTION|API_KEY`, "Configuration Disclosure"},
				}

				for _, pattern := range errorPatterns {
					re := regexp.MustCompile(pattern.pattern)
					if matches := re.FindString(bodyStr); matches != "" {
						vulnerabilities = append(vulnerabilities, model.Vulnerability{
							ID:          "INFO-04",
							Name:        pattern.name,
							Description: "The server reveals sensitive information in error messages",
							Severity:    model.SeverityMedium,
							CVSS:        5.3,
							Detail:      fmt.Sprintf("Error message contains sensitive information: %s", matches),
							Evidence:    fmt.Sprintf("Path: %s, Status: %d", path, resp.StatusCode),
							Remediation: "Configure proper error handling to avoid leaking sensitive information",
							Reference:   "https://www.owasp.org/index.php/Improper_Error_Handling",
						})
						break
					}
				}
			}
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&ServerInfoLeakageModule{})
}
