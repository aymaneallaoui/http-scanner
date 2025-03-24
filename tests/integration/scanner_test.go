package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/core"
	"github.com/aymaneallaoui/kafka-http-scanner/pkg/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestScannerAgainstTestServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Test server</body></html>"))
	}))
	defer ts.Close()

	logger := logrus.New()
	config := core.Config{
		Timeout:         10,
		MaxRetries:      1,
		Concurrency:     2,
		FollowRedirects: true,
		SkipSSLVerify:   true,
	}

	scanner, err := core.NewScanner(config, logger)
	assert.NoError(t, err)

	target, err := utils.ParseURL(ts.URL)
	assert.NoError(t, err)
	scanner.SetTarget(target)

	err = scanner.RunScan()
	assert.NoError(t, err)

	results := scanner.GetResults()

	assert.Greater(t, len(results.Vulnerabilities), 0)
}
