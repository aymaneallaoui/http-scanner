package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Timeout         int               `json:"timeout" yaml:"timeout"`
	MaxRetries      int               `json:"max_retries" yaml:"max_retries"`
	Concurrency     int               `json:"concurrency" yaml:"concurrency"`
	FollowRedirects bool              `json:"follow_redirects" yaml:"follow_redirects"`
	SkipSSLVerify   bool              `json:"skip_ssl_verify" yaml:"skip_ssl_verify"`
	Headers         map[string]string `json:"headers" yaml:"headers"`
	OutputFormat    string            `json:"output_format" yaml:"output_format"`
	LogLevel        string            `json:"log_level" yaml:"log_level"`
	EnabledModules  []string          `json:"enabled_modules" yaml:"enabled_modules"`
	DisabledModules []string          `json:"disabled_modules" yaml:"disabled_modules"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	var config Config

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("error parsing JSON config: %v", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("error parsing YAML config: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}

	return &config, nil
}
