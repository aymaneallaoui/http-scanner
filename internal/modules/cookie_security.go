package modules

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type CookieSecurityModule struct{}

func (m *CookieSecurityModule) Name() string {
	return "CookieSecurity"
}

func (m *CookieSecurityModule) Description() string {
	return "Checks for cookie security issues like missing flags, weak configurations, etc."
}

func (m *CookieSecurityModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	logger := s.GetLogger()
	target := s.GetTarget()

	logger.Debug("Testing for cookie security issues")
	resp, err := s.SendHTTPRequest("GET", "/", nil, nil)
	if err != nil {
		logger.Errorf("Error in CookieSecurity module: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	logger.Debugf("Found %d cookies", len(cookies))

	if len(cookies) == 0 {
		authPaths := []string{"/login", "/signin", "/auth", "/account"}
		for _, path := range authPaths {
			logger.Debugf("Trying path %s for cookies", path)
			authResp, authErr := s.SendHTTPRequest("GET", path, nil, nil)
			if authErr == nil {
				defer authResp.Body.Close()
				cookies = append(cookies, authResp.Cookies()...)
			}
		}
	}

	for _, cookie := range cookies {
		logger.Debugf("Analyzing cookie: %s", cookie.Name)

		if (strings.Contains(strings.ToLower(cookie.Name), "sess") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "token") ||
			cookie.Name == "JSESSIONID" || cookie.Name == "PHPSESSID") &&
			!cookie.Secure && target.SSL {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "COOKIE-01",
				Name:        "Session Cookie Without Secure Flag",
				Description: "A session cookie is set without the Secure flag",
				Severity:    model.SeverityMedium,
				CVSS:        5.8,
				Detail:      fmt.Sprintf("The cookie '%s' appears to be a session cookie but doesn't have the Secure flag set", cookie.Name),
				Evidence:    fmt.Sprintf("Cookie Name: %s, Secure Flag: %t", cookie.Name, cookie.Secure),
				Remediation: "Set the Secure flag for all session cookies",
				Reference:   "https://owasp.org/www-community/controls/SecureCookieAttribute",
			})
		}

		if (strings.Contains(strings.ToLower(cookie.Name), "sess") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "token") ||
			cookie.Name == "JSESSIONID" || cookie.Name == "PHPSESSID") &&
			!cookie.HttpOnly {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "COOKIE-02",
				Name:        "Session Cookie Without HttpOnly Flag",
				Description: "A session cookie is set without the HttpOnly flag",
				Severity:    model.SeverityMedium,
				CVSS:        6.1,
				Detail:      fmt.Sprintf("The cookie '%s' appears to be a session cookie but doesn't have the HttpOnly flag set", cookie.Name),
				Evidence:    fmt.Sprintf("Cookie Name: %s, HttpOnly Flag: %t", cookie.Name, cookie.HttpOnly),
				Remediation: "Set the HttpOnly flag for all session cookies",
				Reference:   "https://owasp.org/www-community/HttpOnly",
			})
		}

		if (strings.Contains(strings.ToLower(cookie.Name), "sess") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "token") ||
			cookie.Name == "JSESSIONID" || cookie.Name == "PHPSESSID") &&
			cookie.SameSite == http.SameSiteNoneMode {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "COOKIE-03",
				Name:        "Session Cookie With Weak SameSite Policy",
				Description: "A session cookie is set with SameSite=None",
				Severity:    model.SeverityLow,
				CVSS:        4.3,
				Detail:      fmt.Sprintf("The cookie '%s' has SameSite=None, which may expose it to CSRF attacks", cookie.Name),
				Evidence:    fmt.Sprintf("Cookie Name: %s, SameSite: None", cookie.Name),
				Remediation: "Set SameSite=Lax or SameSite=Strict for session cookies",
				Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
			})
		}

		if (strings.Contains(strings.ToLower(cookie.Name), "sess") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			cookie.Name == "JSESSIONID" || cookie.Name == "PHPSESSID") &&
			!cookie.Expires.IsZero() {
			expiresIn := cookie.Expires.Sub(time.Now())
			if expiresIn < time.Minute {
				vulnerabilities = append(vulnerabilities, model.Vulnerability{
					ID:          "COOKIE-04",
					Name:        "Session Cookie With Very Short Expiration",
					Description: "A session cookie has a very short expiration time",
					Severity:    model.SeverityLow,
					CVSS:        3.5,
					Detail:      fmt.Sprintf("The cookie '%s' has a very short expiration time of less than 1 minute", cookie.Name),
					Evidence:    fmt.Sprintf("Cookie Name: %s, Expires In: %v", cookie.Name, expiresIn),
					Remediation: "Set appropriate expiration times for session cookies",
					Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
				})
			} else if expiresIn > 24*time.Hour {
				vulnerabilities = append(vulnerabilities, model.Vulnerability{
					ID:          "COOKIE-05",
					Name:        "Session Cookie With Long Expiration",
					Description: "A session cookie has a long expiration time",
					Severity:    model.SeverityLow,
					CVSS:        3.7,
					Detail:      fmt.Sprintf("The cookie '%s' has a long expiration time of more than 24 hours", cookie.Name),
					Evidence:    fmt.Sprintf("Cookie Name: %s, Expires In: %v", cookie.Name, expiresIn),
					Remediation: "Set appropriate expiration times for session cookies",
					Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
				})
			}
		}
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&CookieSecurityModule{})
}
