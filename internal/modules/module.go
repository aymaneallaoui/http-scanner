package modules

import (
	"io"
	"net/http"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
	"github.com/sirupsen/logrus"
)

type ScanModule interface {
	Name() string
	Description() string
	Run(scanner Scanner) ([]model.Vulnerability, error)
}

type Scanner interface {
	GetTarget() model.Target
	SendHTTPRequest(method, path string, headers map[string]string, body io.Reader) (*http.Response, error)
	SendRawRequest(payload string) (string, error)
	GetLogger() *logrus.Logger
}
