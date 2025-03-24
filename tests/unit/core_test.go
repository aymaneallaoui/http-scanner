package unit

import (
	"testing"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/core"
	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewScanner(t *testing.T) {
	logger := logrus.New()
	config := core.Config{
		Timeout:     10,
		MaxRetries:  3,
		Concurrency: 5,
	}

	scanner, err := core.NewScanner(config, logger)
	assert.NoError(t, err)
	assert.NotNil(t, scanner)
}

func TestCalculateStats(t *testing.T) {
	logger := logrus.New()
	config := core.Config{
		Timeout:     10,
		MaxRetries:  3,
		Concurrency: 5,
	}

	scanner, _ := core.NewScanner(config, logger)

	scanner.AddVulnerability(model.Vulnerability{Severity: model.SeverityHigh})
	scanner.AddVulnerability(model.Vulnerability{Severity: model.SeverityMedium})
	scanner.AddVulnerability(model.Vulnerability{Severity: model.SeverityLow})
	scanner.AddVulnerability(model.Vulnerability{Severity: model.SeverityCritical})
	scanner.AddVulnerability(model.Vulnerability{Severity: model.SeverityInfo})

	result := scanner.GetResults()

	assert.Equal(t, 1, result.Stats.Critical)
	assert.Equal(t, 1, result.Stats.High)
	assert.Equal(t, 1, result.Stats.Medium)
	assert.Equal(t, 1, result.Stats.Low)
	assert.Equal(t, 1, result.Stats.Info)
	assert.Equal(t, 5, result.Stats.Total)
}
