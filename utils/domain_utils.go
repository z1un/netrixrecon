package utils

import (
	"regexp"
	"strings"
)

var (
	reLeadingNum = regexp.MustCompile(`^\d+\s+`)
	reHTTP       = regexp.MustCompile(`^https?://`)
	reBacktick   = regexp.MustCompile("`")
	reDomain     = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
)

func IsValidDomain(host string) bool {
	if host == "" {
		return false
	}
	cleaned := reLeadingNum.ReplaceAllString(host, "")
	if !reDomain.MatchString(cleaned) {
		return false
	}
	if !strings.Contains(cleaned, ".") {
		return false
	}
	if cleaned[0] == '.' || cleaned[0] == '-' || cleaned[len(cleaned)-1] == '.' || cleaned[len(cleaned)-1] == '-' {
		return false
	}
	return true
}

func findColon(s string) int {
	hasBracket := false
	for i, c := range s {
		if c == '[' {
			hasBracket = true
		} else if c == ']' {
			hasBracket = false
		} else if c == ':' && !hasBracket {
			return i
		}
	}
	return -1
}

func CleanDomain(host string) string {
	host = reHTTP.ReplaceAllString(host, "")
	host = reBacktick.ReplaceAllString(host, "")
	if idx := findColon(host); idx >= 0 {
		host = host[:idx]
	}
	return host
}
