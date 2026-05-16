package utils

import (
	"os"
	"time"
)

const (
	DefaultThreads = 200
	DNSTimeout     = 5 * time.Second
)

var DefaultNameservers = []string{"8.8.8.8:53", "1.1.1.1:53"}

func GetFOFAKey() string        { return os.Getenv("FOFA_API_KEY") }
func GetDNSDumpsterKey() string { return os.Getenv("DNSDUMPSTER_API_KEY") }
func GetVirusTotalKey() string  { return os.Getenv("VIRUSTOTAL_API_KEY") }

func GetFOFAQuery() string {
	if q := os.Getenv("FOFA_QUERY"); q != "" {
		return q
	}
	return `(domain="%s" || host="%s" || cert="%s" || banner="%s" || title="%s")`
}
