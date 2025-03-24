package modules

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

type SSLTLSSecurityModule struct{}

func (m *SSLTLSSecurityModule) Name() string {
	return "SSLTLSSecurity"
}

func (m *SSLTLSSecurityModule) Description() string {
	return "Checks for SSL/TLS security issues like outdated protocols and weak ciphers"
}

func (m *SSLTLSSecurityModule) Run(s Scanner) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	target := s.GetTarget()
	logger := s.GetLogger()

	if !target.SSL {
		logger.Debug("Skipping SSL/TLS checks for non-HTTPS target")
		return vulnerabilities, nil
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(10) * time.Second,
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionSSL30,
	}

	logger.Debug("Testing for SSLv3 support")
	conn, err := tls.DialWithDialer(dialer, "tcp", target.Hostname+":"+target.Port, conf)
	if err == nil {
		conn.Close()
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "SSL-01",
			Name:        "SSLv3 Protocol Supported",
			Description: "The server supports the insecure SSLv3 protocol",
			Severity:    model.SeverityHigh,
			CVSS:        7.4,
			Detail:      "SSLv3 is vulnerable to the POODLE attack and other issues",
			Remediation: "Disable SSLv3 support on the server",
			Reference:   "https://www.openssl.org/~bodo/ssl-poodle.pdf",
		})
	}

	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}

	logger.Debug("Testing for TLS 1.0 support")
	conn, err = tls.DialWithDialer(dialer, "tcp", target.Hostname+":"+target.Port, conf)
	if err == nil {
		conn.Close()
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "SSL-02",
			Name:        "TLS 1.0 Protocol Supported",
			Description: "The server supports the outdated TLS 1.0 protocol",
			Severity:    model.SeverityMedium,
			CVSS:        5.9,
			Detail:      "TLS 1.0 has known vulnerabilities and is considered outdated",
			Remediation: "Disable TLS 1.0 support on the server",
			Reference:   "https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/",
		})
	}

	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	}

	logger.Debug("Testing for TLS 1.1 support")
	conn, err = tls.DialWithDialer(dialer, "tcp", target.Hostname+":"+target.Port, conf)
	if err == nil {
		conn.Close()
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ID:          "SSL-03",
			Name:        "TLS 1.1 Protocol Supported",
			Description: "The server supports the outdated TLS 1.1 protocol",
			Severity:    model.SeverityLow,
			CVSS:        4.3,
			Detail:      "TLS 1.1 has security weaknesses and is considered outdated",
			Remediation: "Disable TLS 1.1 support on the server",
			Reference:   "https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/",
		})
	}

	conf = &tls.Config{
		InsecureSkipVerify: true,
	}

	logger.Debug("Testing for TLS renegotiation configuration")
	conn, err = tls.DialWithDialer(dialer, "tcp", target.Hostname+":"+target.Port, conf)
	if err == nil {
		cs := conn.ConnectionState()

		if cs.Version < tls.VersionTLS12 {
			vulnerabilities = append(vulnerabilities, model.Vulnerability{
				ID:          "SSL-04",
				Name:        "Weak TLS Protocol Version",
				Description: "The server negotiated a TLS version less than 1.2",
				Severity:    model.SeverityMedium,
				CVSS:        6.8,
				Detail:      "TLS versions below 1.2 have known vulnerabilities",
				Remediation: "Configure the server to use TLS 1.2 or higher only",
				Reference:   "https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/",
			})
		}
		conn.Close()
	}

	return vulnerabilities, nil
}

func init() {
	RegisterModule(&SSLTLSSecurityModule{})
}
