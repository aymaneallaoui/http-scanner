package utils

import (
	"regexp"
	"strings"
)

func ExtractRegex(pattern, text string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func MatchRegex(pattern, text string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(text)
}

func ContainsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

// ContainsAll checks if the text contains all of the provided patterns
func ContainsAll(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if !strings.Contains(text, pattern) {
			return false
		}
	}
	return true
}
