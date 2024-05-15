GoHTTPSecScanner
An advanced HTTP security vulnerability scanner that detects a wide range of web application vulnerabilities.
Features

Comprehensive Vulnerability Detection: Identifies HTTP smuggling, XSS, SQL injection, and many other vulnerabilities
Modular Architecture: Easy to extend with new vulnerability checks
Concurrent Scanning: Fast multi-threaded testing
Multiple Output Formats: Results in text, JSON, or YAML
Detailed Remediation: Provides actionable fixes for discovered vulnerabilities
Production-Ready: Robust error handling and retry mechanisms
Installation
From Source

# Clone the repository

git clone https://github.com/aymaneallaoui/go-http-scanner.git
cd go-http-scanner

# Build the project

go build -o httpscan

# Make it available system-wide (optional)

sudo mv httpscan /usr/local/bin/
Using Go Install
Quick Start

go install github.com/aymaneallaoui/go-http-scanner@latest

Available Modules
ModuleDescriptionHeaderSecurityChecks for missing or insecure HTTP security headersHttpSmugglingDetects HTTP request smuggling vulnerabilitiesSSLTLSSecurityChecks for SSL/TLS security issues like outdated protocols and weak ciphersContentSecurityChecks for content security issues like MIME type confusionHTTPMethodsChecks for support of dangerous HTTP methodsServerInfoLeakageChecks for server information leakageXSSVulnerabilityChecks for Cross-Site Scripting vulnerabilitiesSQLInjectionChecks for SQL injection vulnerabilitiesDirectoryTraversalChecks for directory traversal vulnerabilitiesHostHeaderAttackChecks for host header attack vulnerabilitiesCORSMisconfigurationChecks for CORS misconfigurationsCacheAttackChecks for web cache poisoning vulnerabilitiesWebCacheDeceptionChecks for web cache deception vulnerabilitiesOpenRedirectChecks for open redirect vulnerabilitiesClickjackingChecks for clickjacking vulnerabilitiesCookieSecurityChecks for cookie security issues

# Example configuration file (configs/default.yaml)

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
