package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/z1un/netrixrecon/utils"
)

type Module struct {
	Name string
	API  interface {
		ExtractAssets(domain string) (domains, ips []string, err error)
	}
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

func LoadEnabledAPIs(silent bool) []Module {
	var modules []Module

	ts := utils.Timestamp

	if key := utils.GetFOFAKey(); key != "" {
		modules = append(modules, Module{"FOFA", NewFofaAPI(key)})
	} else if !silent {
		utils.WarnPrintf("[%s] [WARN] FOFA: skipped (FOFA_API_KEY not set)\n", ts())
	}

	if key := utils.GetDNSDumpsterKey(); key != "" {
		modules = append(modules, Module{"DNSDUMPSTER", NewDNSDumpsterAPI(key)})
	} else if !silent {
		utils.WarnPrintf("[%s] [WARN] DNSDUMPSTER: skipped (DNSDUMPSTER_API_KEY not set)\n", ts())
	}

	if key := utils.GetVirusTotalKey(); key != "" {
		modules = append(modules, Module{"VIRUSTOTAL", NewVirusTotalAPI(key)})
	} else if !silent {
		utils.WarnPrintf("[%s] [WARN] VIRUSTOTAL: skipped (VIRUSTOTAL_API_KEY not set)\n", ts())
	}

	if !silent {
		utils.InfoPrintf("[%s] [INFO] CRTSH: enabled (no API key required)\n", ts())
	}
	modules = append(modules, Module{"CRTSH", NewCrtShAPI()})

	return modules
}
