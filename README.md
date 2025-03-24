# Kafka HTTP Scanner

![terminal](docs/image/terminal.png)

An advanced HTTP security vulnerability scanner that detects a wide range of web application vulnerabilities.

## Features

- **Comprehensive Vulnerability Detection:** Identifies HTTP smuggling, XSS, SQL injection, and many other vulnerabilities.
- **Modular Architecture:** Easy to extend with new vulnerability checks.
- **Concurrent Scanning:** Fast multi-threaded testing.
- **Multiple Output Formats:** Results in text, JSON, or YAML.
- **Detailed Remediation:** Provides actionable fixes for discovered vulnerabilities.
- **Production-Ready:** Robust error handling and retry mechanisms.

## Installation

### From Source

```sh
git clone https://github.com/aymaneallaoui/go-http-scanner.git
cd go-http-scanner

go build -o httpscan

sudo mv httpscan /usr/local/bin/
```

## Supported modules

| Module                   | Description                                                                  | Severity |
| ------------------------ | ---------------------------------------------------------------------------- | -------- |
| **HeaderSecurity**       | Checks for missing or insecure HTTP security headers.                        | Medium   |
| **HttpSmuggling**        | Detects HTTP request smuggling vulnerabilities.                              | High     |
| **SSLTLSSecurity**       | Checks for SSL/TLS security issues like outdated protocols and weak ciphers. | High     |
| **ContentSecurity**      | Checks for content security issues like MIME type confusion.                 | Medium   |
| **HTTPMethods**          | Checks for support of dangerous HTTP methods.                                | Medium   |
| **ServerInfoLeakage**    | Checks for server information leakage.                                       | Low      |
| **XSSVulnerability**     | Checks for Cross-Site Scripting vulnerabilities.                             | High     |
| **SQLInjection**         | Checks for SQL injection vulnerabilities.                                    | High     |
| **DirectoryTraversal**   | Checks for directory traversal vulnerabilities.                              | High     |
| **HostHeaderAttack**     | Checks for host header attack vulnerabilities.                               | Medium   |
| **CORSMisconfiguration** | Checks for CORS misconfigurations.                                           | Medium   |
| **CacheAttack**          | Checks for web cache poisoning vulnerabilities.                              | Medium   |
| **WebCacheDeception**    | Checks for web cache deception vulnerabilities.                              | Medium   |
| **OpenRedirect**         | Checks for open redirect vulnerabilities.                                    | Medium   |
| **Clickjacking**         | Checks for clickjacking vulnerabilities.                                     | Medium   |
| **CookieSecurity**       | Checks for cookie security issues.                                           | Medium   |

## Example Configuration File (configs/default.yaml)

```yaml
timeout: 10
max_retries: 3
concurrency: 5
follow_redirects: true
skip_ssl_verify: false
output_format: text
log_level: info
enabled_modules:
  - HeaderSecurity
  - HttpSmuggling
  - SSLTLSSecurity
disabled_modules:
  - ServerInfoLeakage
```
