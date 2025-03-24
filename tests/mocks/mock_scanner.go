package mocks

import (
	"io"
	"net/http"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
	"github.com/sirupsen/logrus"
)

type MockScanner struct {
	Target        model.Target
	MockResponses map[string]string
	MockHTTPResp  *http.Response
	Logger        *logrus.Logger
}

func NewMockScanner() *MockScanner {
	return &MockScanner{
		Target: model.Target{
			URL:      "https://example.com",
			Hostname: "example.com",
			Port:     "443",
			SSL:      true,
			Path:     "/",
			Headers:  make(map[string]string),
		},
		MockResponses: make(map[string]string),
		Logger:        logrus.New(),
	}
}

func (m *MockScanner) GetTarget() model.Target {
	return m.Target
}

func (m *MockScanner) SendHTTPRequest(method, path string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return m.MockHTTPResp, nil
}

func (m *MockScanner) SendRawRequest(payload string) (string, error) {
	return "HTTP/1.1 200 OK\r\nServer: Mock\r\nContent-Type: text/html\r\n\r\n<html><body>Mock Response</body></html>", nil
}

func (m *MockScanner) GetLogger() *logrus.Logger {
	return m.Logger
}
