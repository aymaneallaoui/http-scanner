package unit

import (
	"net/http"
	"testing"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/modules"
	"github.com/aymaneallaoui/kafka-http-scanner/tests/mocks"
	"github.com/stretchr/testify/assert"
)

func TestHeaderSecurityModule(t *testing.T) {
	mockScanner := mocks.NewMockScanner()

	headers := http.Header{}
	mockScanner.MockHTTPResp = &http.Response{
		StatusCode: 200,
		Header:     headers,
		Body:       http.NoBody,
	}

	module := &modules.HeaderSecurityModule{}

	vulnerabilities, err := module.Run(mockScanner)

	assert.NoError(t, err)
	assert.Greater(t, len(vulnerabilities), 0)

	var foundXFrameOptions bool
	var foundCSP bool

	for _, vuln := range vulnerabilities {
		if vuln.ID == "HEADER-01" {
			foundXFrameOptions = true
		}
		if vuln.ID == "HEADER-02" {
			foundCSP = true
		}
	}

	assert.True(t, foundXFrameOptions, "Should find missing X-Frame-Options header")
	assert.True(t, foundCSP, "Should find missing Content-Security-Policy header")
}
