package utils

import "regexp"

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
	return reDomain.MatchString(cleaned)
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
