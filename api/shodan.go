package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/z1un/netrixrecon/utils"
)

type ShodanAPI struct {
	apiKey string
	client *http.Client
}

func NewShodanAPI(apiKey string) *ShodanAPI {
	return &ShodanAPI{
		apiKey: apiKey,
		client: newHTTPClient(),
	}
}

type shodanDNSResponse struct {
	Domain     string           `json:"domain"`
	Subdomains []string         `json:"subdomains"`
	Data       []shodanDNSRecord `json:"data"`
}

type shodanDNSRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

func (s *ShodanAPI) ExtractAssets(domain string) ([]string, []string, error) {
	u := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s",
		url.PathEscape(domain), url.QueryEscape(s.apiKey))

	resp, err := s.client.Get(u)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var sr shodanDNSResponse
	if err := json.Unmarshal(bodyBytes, &sr); err != nil {
		return nil, nil, jsonDecodeError(resp.StatusCode, bodyBytes, err)
	}

	domains := make(map[string]struct{})
	ips := make(map[string]struct{})

	for _, sub := range sr.Subdomains {
		d := sub + "." + domain
		if utils.IsValidDomain(d) {
			domains[d] = struct{}{}
		}
	}

	for _, record := range sr.Data {
		if record.Subdomain != "" {
			d := record.Subdomain + "." + domain
			if utils.IsValidDomain(d) {
				domains[d] = struct{}{}
			}
		}

		if record.Type == "A" || record.Type == "AAAA" {
			if utils.IsValidIP(record.Value) {
				ips[record.Value] = struct{}{}
			}
		} else if record.Type == "CNAME" {
			if utils.IsValidDomain(record.Value) {
				domains[record.Value] = struct{}{}
			}
		}
	}

	return mapKeys(domains), mapKeys(ips), nil
}
