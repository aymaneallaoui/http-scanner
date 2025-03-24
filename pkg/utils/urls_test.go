package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseURL(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		expectedURL  string
		expectedHost string
		expectedPort string
		expectedSSL  bool
		expectedPath string
		expectError  bool
	}{
		{
			name:         "Simple HTTP URL",
			input:        "http://example.com",
			expectedURL:  "http://example.com",
			expectedHost: "example.com",
			expectedPort: "80",
			expectedSSL:  false,
			expectedPath: "/",
			expectError:  false,
		},
		{
			name:         "HTTPS URL",
			input:        "https://example.com",
			expectedURL:  "https://example.com",
			expectedHost: "example.com",
			expectedPort: "443",
			expectedSSL:  true,
			expectedPath: "/",
			expectError:  false,
		},
		{
			name:         "URL with path",
			input:        "https://example.com/test/path",
			expectedURL:  "https://example.com/test/path",
			expectedHost: "example.com",
			expectedPort: "443",
			expectedSSL:  true,
			expectedPath: "/test/path",
			expectError:  false,
		},
		{
			name:         "URL with custom port",
			input:        "http://example.com:8080",
			expectedURL:  "http://example.com:8080",
			expectedHost: "example.com",
			expectedPort: "8080",
			expectedSSL:  false,
			expectedPath: "/",
			expectError:  false,
		},
		{
			name:         "URL without scheme",
			input:        "example.com",
			expectedURL:  "http://example.com",
			expectedHost: "example.com",
			expectedPort: "80",
			expectedSSL:  false,
			expectedPath: "/",
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ParseURL(tc.input)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedURL, target.URL)
				assert.Equal(t, tc.expectedHost, target.Hostname)
				assert.Equal(t, tc.expectedPort, target.Port)
				assert.Equal(t, tc.expectedSSL, target.SSL)
				assert.Equal(t, tc.expectedPath, target.Path)
			}
		})
	}
}
