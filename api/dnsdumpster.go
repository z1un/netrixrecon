package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/z1un/netrixrecon/utils"
)

var (
	reLeading   = regexp.MustCompile(`^\d+\s+`)
	reIP4       = regexp.MustCompile(`ip4:([\d.]+(?:/\d+)?)`)
	reDomainRef = regexp.MustCompile(`(?:include|a|mx):([a-zA-Z0-9.-]+)`)
)

type DNSDumpsterAPI struct {
	apiKey string
	client *http.Client
}

func NewDNSDumpsterAPI(apiKey string) *DNSDumpsterAPI {
	return &DNSDumpsterAPI{
		apiKey: apiKey,
		client: newHTTPClient(),
	}
}

func (d *DNSDumpsterAPI) ExtractAssets(domain string) ([]string, []string, error) {
	url := fmt.Sprintf("https://api.dnsdumpster.com/domain/%s", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-API-Key", d.apiKey)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, nil, jsonDecodeError(resp.StatusCode, bodyBytes, err)
	}

	domains := make(map[string]struct{})
	ips := make(map[string]struct{})
	var networks []string

	extractHost := func(host string) string {
		return reLeading.ReplaceAllString(host, "")
	}

	if aRecords, ok := data["a"].([]interface{}); ok {
		for _, item := range aRecords {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if host, ok := m["host"].(string); ok {
				cleaned := extractHost(host)
				if utils.IsValidDomain(cleaned) {
					domains[cleaned] = struct{}{}
				}
			}
			if ipsList, ok := m["ips"].([]interface{}); ok {
				for _, ipItem := range ipsList {
					ipMap, ok := ipItem.(map[string]interface{})
					if !ok {
						continue
					}
					if ip, ok := ipMap["ip"].(string); ok && utils.IsValidIP(ip) {
						if !utils.IsIPInNetworks(ip, networks) {
							ips[ip] = struct{}{}
						}
					}
				}
			}
		}
	}

	for _, section := range []string{"ns", "mx"} {
		records, ok := data[section].([]interface{})
		if !ok {
			continue
		}
		for _, item := range records {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if host, ok := m["host"].(string); ok {
				cleaned := extractHost(host)
				if utils.IsValidDomain(cleaned) {
					domains[cleaned] = struct{}{}
				}
			}
		}
	}

	if txtRecords, ok := data["txt"].([]interface{}); ok {
		for _, txtItem := range txtRecords {
			txt, ok := txtItem.(string)
			if !ok {
				continue
			}

			matches := reIP4.FindAllStringSubmatch(txt, -1)
			for _, m := range matches {
				entry := m[1]
				if utils.IsValidIP(entry) {
					if !utils.IsIPInNetworks(entry, networks) {
						ips[entry] = struct{}{}
					}
				} else if _, err := netip.ParsePrefix(entry); err == nil {
					networks = append(networks, entry)
					for ip := range ips {
						if utils.IsIPInNetworks(ip, []string{entry}) {
							delete(ips, ip)
						}
					}
				}
			}

			domainMatches := reDomainRef.FindAllStringSubmatch(txt, -1)
			for _, m := range domainMatches {
				if utils.IsValidDomain(m[1]) {
					domains[m[1]] = struct{}{}
				}
			}
		}
	}

	for ip := range ips {
		if utils.IsIPInNetworks(ip, networks) {
			delete(ips, ip)
		}
	}

	return mapKeys(domains), mapKeys(ips), nil
}
