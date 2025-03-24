package utils

import (
	"net/url"
	"strings"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

func ParseURL(rawURL string) (model.Target, error) {
	target := model.Target{
		Headers: make(map[string]string),
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return target, err
	}

	target.URL = rawURL
	target.Hostname = parsedURL.Hostname()
	target.SSL = parsedURL.Scheme == "https"
	target.Path = parsedURL.Path
	if target.Path == "" {
		target.Path = "/"
	}

	if parsedURL.Port() == "" {
		if target.SSL {
			target.Port = "443"
		} else {
			target.Port = "80"
		}
	} else {
		target.Port = parsedURL.Port()
	}

	return target, nil
}
