package core

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	customhttp "github.com/aymaneallaoui/kafka-http-scanner/internal/http"
	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
	"github.com/aymaneallaoui/kafka-http-scanner/internal/modules"
	"github.com/sirupsen/logrus"
)

type Scanner struct {
	config     Config
	target     model.Target
	result     model.ScanResult
	httpClient *customhttp.Client
	logger     *logrus.Logger
	mu         sync.Mutex
	wg         sync.WaitGroup
	semaphore  chan struct{}
}

func NewScanner(config Config, logger *logrus.Logger) (*Scanner, error) {
	scanner := &Scanner{
		config: config,
		logger: logger,
		result: model.ScanResult{
			Vulnerabilities: []model.Vulnerability{},
		},
	}

	httpClient, err := customhttp.NewClient(config.Timeout, config.MaxRetries, config.FollowRedirects, config.SkipSSLVerify)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP client: %v", err)
	}
	scanner.httpClient = httpClient

	scanner.semaphore = make(chan struct{}, config.Concurrency)

	return scanner, nil
}

func (s *Scanner) SetTarget(target model.Target) {
	s.target = target
}

func (s *Scanner) GetTarget() model.Target {
	return s.target
}

func (s *Scanner) GetResults() model.ScanResult {
	s.calculateStats()
	return s.result
}

func (s *Scanner) RunScan() error {
	availableModules := modules.GetModules()
	s.logger.Debugf("Found %d scan modules", len(availableModules))

	var modulesToRun []modules.ScanModule
	for _, module := range availableModules {
		name := module.Name()

		if contains(s.config.DisabledModules, name) {
			s.logger.Debugf("Skipping disabled module: %s", name)
			continue
		}

		if len(s.config.EnabledModules) > 0 && !contains(s.config.EnabledModules, name) {
			s.logger.Debugf("Skipping module not in enabled list: %s", name)
			continue
		}

		modulesToRun = append(modulesToRun, module)
	}

	s.logger.Infof("Running %d modules", len(modulesToRun))

	for _, module := range modulesToRun {
		s.wg.Add(1)
		go func(m modules.ScanModule) {
			defer s.wg.Done()

			s.semaphore <- struct{}{}
			defer func() { <-s.semaphore }()

			s.logger.Debugf("Running module: %s", m.Name())

			vulnerabilityChan := make(chan []model.Vulnerability, 1)
			errorChan := make(chan error, 1)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Errorf("Module %s panicked: %v", m.Name(), r)
						errorChan <- fmt.Errorf("module %s panicked: %v", m.Name(), r)
					}
				}()

				vulnerabilities, err := m.Run(s)
				if err != nil {
					errorChan <- err
					return
				}
				vulnerabilityChan <- vulnerabilities
			}()

			select {
			case vulnerabilities := <-vulnerabilityChan:
				if len(vulnerabilities) > 0 {
					s.mu.Lock()
					s.result.Vulnerabilities = append(s.result.Vulnerabilities, vulnerabilities...)
					s.mu.Unlock()
					s.logger.Infof("Module %s found %d vulnerabilities", m.Name(), len(vulnerabilities))
				} else {
					s.logger.Debugf("Module %s found no vulnerabilities", m.Name())
				}
			case err := <-errorChan:
				s.logger.Errorf("Error in module %s: %v", m.Name(), err)
			case <-time.After(time.Duration(s.config.Timeout*2) * time.Second):
				s.logger.Errorf("Module %s timed out", m.Name())
			}
		}(module)
	}

	s.wg.Wait()

	return nil
}

func (s *Scanner) calculateStats() {
	for _, vuln := range s.result.Vulnerabilities {
		switch vuln.Severity {
		case model.SeverityCritical:
			s.result.Stats.Critical++
		case model.SeverityHigh:
			s.result.Stats.High++
		case model.SeverityMedium:
			s.result.Stats.Medium++
		case model.SeverityLow:
			s.result.Stats.Low++
		case model.SeverityInfo:
			s.result.Stats.Info++
		}
	}
	s.result.Stats.Total = len(s.result.Vulnerabilities)
}

func (s *Scanner) AddVulnerability(vuln model.Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.Vulnerabilities = append(s.result.Vulnerabilities, vuln)
}

func (s *Scanner) SendHTTPRequest(method, path string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return s.httpClient.SendRequest(s.target, method, path, headers, body)
}

func (s *Scanner) SendRawRequest(payload string) (string, error) {
	return s.httpClient.SendRawRequest(s.target, payload)
}

func (s *Scanner) GetLogger() *logrus.Logger {
	return s.logger
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(strings.ToLower(s)) == strings.TrimSpace(strings.ToLower(item)) {
			return true
		}
	}
	return false
}
