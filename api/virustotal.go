package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type VirusTotalAPI struct {
	apiKey string
	client *http.Client
}

func NewVirusTotalAPI(apiKey string) *VirusTotalAPI {
	return &VirusTotalAPI{
		apiKey: apiKey,
		client: newHTTPClient(),
	}
}

type vtSubdomain struct {
	ID         string       `json:"id"`
	Attributes vtAttributes `json:"attributes"`
}

type vtAttributes struct {
	LastDNSRecords []vtDNSRecord `json:"last_dns_records"`
}

type vtDNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type vtResponse struct {
	Data  []vtSubdomain `json:"data"`
	Links vtLinks       `json:"links"`
}

type vtLinks struct {
	Next string `json:"next"`
}

func (v *VirusTotalAPI) ExtractAssets(domain string) ([]string, []string, error) {
	domains := make(map[string]struct{})
	ips := make(map[string]struct{})
	nextURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", domain)

	for nextURL != "" {
		req, _ := http.NewRequest("GET", nextURL, nil)
		req.Header.Set("accept", "application/json")
		req.Header.Set("x-apikey", v.apiKey)

		resp, err := v.client.Do(req)
		if err != nil {
			return nil, nil, err
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read response body: %w", err)
		}

		var vtResp vtResponse
		if err := json.Unmarshal(bodyBytes, &vtResp); err != nil {
			return nil, nil, jsonDecodeError(resp.StatusCode, bodyBytes, err)
		}

		for _, item := range vtResp.Data {
			if item.ID != "" {
				domains[item.ID] = struct{}{}
			}
			for _, record := range item.Attributes.LastDNSRecords {
				if record.Type == "A" && record.Value != "" {
					ips[record.Value] = struct{}{}
				}
			}
		}

		nextURL = vtResp.Links.Next
	}

	return mapKeys(domains), mapKeys(ips), nil
}
