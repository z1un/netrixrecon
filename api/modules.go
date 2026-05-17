package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/z1un/netrixrecon/utils"
)

type Module struct {
	Name   string
	API    interface{ ExtractAssets(domain string) (domains, ips []string, err error) }
	Reason string
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func jsonDecodeError(statusCode int, body []byte, err error) error {
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	return fmt.Errorf("status %d, JSON decode failed: %v (body: %s)", statusCode, err, snippet)
}

func LoadEnabledAPIs() []Module {
	return []Module{
		{Name: "FOFA", API: fofaAPI(), Reason: fofaReason()},
		{Name: "DNSDUMPSTER", API: dnsdumpsterAPI(), Reason: dnsdumpsterReason()},
		{Name: "VIRUSTOTAL", API: virustotalAPI(), Reason: virustotalReason()},
		{Name: "CRTSH", API: NewCrtShAPI()},
		{Name: "SHODAN", API: shodanAPI(), Reason: shodanReason()},
	}
}

func fofaAPI() interface{ ExtractAssets(domain string) (domains, ips []string, err error) } {
	if key := utils.GetFOFAKey(); key != "" {
		return NewFofaAPI(key)
	}
	return nil
}

func fofaReason() string {
	if utils.GetFOFAKey() == "" {
		return "FOFA_API_KEY not set"
	}
	return ""
}

func dnsdumpsterAPI() interface{ ExtractAssets(domain string) (domains, ips []string, err error) } {
	if key := utils.GetDNSDumpsterKey(); key != "" {
		return NewDNSDumpsterAPI(key)
	}
	return nil
}

func dnsdumpsterReason() string {
	if utils.GetDNSDumpsterKey() == "" {
		return "DNSDUMPSTER_API_KEY not set"
	}
	return ""
}

func virustotalAPI() interface{ ExtractAssets(domain string) (domains, ips []string, err error) } {
	if key := utils.GetVirusTotalKey(); key != "" {
		return NewVirusTotalAPI(key)
	}
	return nil
}

func virustotalReason() string {
	if utils.GetVirusTotalKey() == "" {
		return "VIRUSTOTAL_API_KEY not set"
	}
	return ""
}

func shodanAPI() interface{ ExtractAssets(domain string) (domains, ips []string, err error) } {
	if key := utils.GetShodanKey(); key != "" {
		return NewShodanAPI(key)
	}
	return nil
}

func shodanReason() string {
	if utils.GetShodanKey() == "" {
		return "SHODAN_API_KEY not set"
	}
	return ""
}
