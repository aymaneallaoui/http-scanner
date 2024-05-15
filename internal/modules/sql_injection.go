package modules

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
)

type SQLInjectionModule struct{}

func (m *SQLInjectionModule) Name() string {
	return "SQLInjection"
}

func (m *SQLInjectionModule) Description() string {
	return "Checks for SQL Injection vulnerabilities"
}

func (m *SQLInjectionModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()

	payloads := []string{
		"'",
		"' OR '1'='1",
		"' OR 1=1--",
		"'; DROP TABLE users--",
		"1' ORDER BY 1--",
		"1' UNION SELECT 1,2,3--",
		"' OR 1=1 LIMIT 1;--",
		"' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
		"'; WAITFOR DELAY '0:0:2'--",
	}

	testPaths := []string{
		"/?id=PAYLOAD",
		"/search?q=PAYLOAD",
		"/index.php?id=PAYLOAD",
		"/product?id=PAYLOAD",
		"/page?id=PAYLOAD",
	}

	for _, path := range testPaths {
		for _, payload := range payloads {
			testPath := strings.Replace(path, "PAYLOAD", url.QueryEscape(payload), 1)
			logger.Debugf("Testing SQL injection with path: %s", testPath)

			startTime := time.Now()
			resp, err := s.SendHTTPRequest("GET", testPath, nil, nil)

			if err != nil {
				logger.Debugf("Error requesting %s: %v", testPath, err)
				continue
			}

			duration := time.Since(startTime)
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logger.Debugf("Error reading response body: %v", err)
				continue
			}

			bodyStr := string(body)

			sqlErrorPatterns := []string{
				"SQL syntax.*?error",
				"Warning.*?\\Wmysqli?_",
				"MySQLSyntaxErrorException",
				"Valid MySQL result",
				"ORA-[0-9]+",
				"Oracle.*?Driver",
				"SQLSTATE\\[",
				"Microsoft SQL Server",
				"PostgreSQL.*?ERROR",
				"PG::SyntaxError:",
				"Unclosed quotation mark after",
				"SQLite3::query",
				"System\\.Data\\.SQLite\\.SQLiteException",
			}

			for _, pattern := range sqlErrorPatterns {
				re := regexp.MustCompile("(?i)" + pattern)
				if matches := re.FindString(bodyStr); matches != "" {
					vulnerabilities = append(vulnerabilities, model.Vulnerability{
						ID:          "SQLI-01",
						Name:        "SQL Injection",
						Description: "The application appears vulnerable to SQL injection",
						Severity:    model.SeverityCritical,
						CVSS:        9.1,
						Detail:      "The application returned SQL error messages when supplied with malicious input",
						Evidence:    fmt.Sprintf("Payload: %s, Error: %s", payload, matches),
						Remediation: "Use parameterized queries or prepared statements",
						Reference:   "https://owasp.org/www-community/attacks/SQL_Injection",
					})
					return vulnerabilities, nil
				}
			}

			if strings.Contains(payload, "SLEEP") || strings.Contains(payload, "WAITFOR DELAY") {
				if duration.Seconds() > 1.5 {
					vulnerabilities = append(vulnerabilities, model.Vulnerability{
						ID:          "SQLI-02",
						Name:        "Time-Based Blind SQL Injection",
						Description: "The application appears vulnerable to time-based blind SQL injection",
						Severity:    model.SeverityCritical,
						CVSS:        8.5,
						Detail:      "The application response time increased significantly with a time-delay SQL payload",
						Evidence:    fmt.Sprintf("Payload: %s, Response time: %v seconds", payload, duration.Seconds()),
						Remediation: "Use parameterized queries or prepared statements",
						Reference:   "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
					})
					return vulnerabilities, nil
				}
			}
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&SQLInjectionModule{})
}
