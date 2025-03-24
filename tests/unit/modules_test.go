package unit

import (
	"testing"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
	"github.com/aymaneallaoui/kafka-http-scanner/internal/modules"
	"github.com/stretchr/testify/assert"
)

func TestModuleRegistry(t *testing.T) {
	modules.ResetModuleRegistry()

	testModule := &TestModule{}

	modules.RegisterModule(testModule)

	registeredModules := modules.GetModules()
	assert.Equal(t, 1, len(registeredModules))

	retrievedModule, found := modules.GetModule("TestModule")
	assert.True(t, found)
	assert.Equal(t, testModule, retrievedModule)
}

type TestModule struct{}

func (m *TestModule) Name() string {
	return "TestModule"
}

func (m *TestModule) Description() string {
	return "Test module for unit tests"
}

func (m *TestModule) Run(scanner modules.Scanner) ([]model.Vulnerability, error) {
	return []model.Vulnerability{}, nil
}
