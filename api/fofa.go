package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/z1un/netrixrecon/utils"
)

type FofaAPI struct {
	apiKey string
	client *http.Client
}

func NewFofaAPI(apiKey string) *FofaAPI {
	return &FofaAPI{
		apiKey: apiKey,
		client: newHTTPClient(),
	}
}

type fofaResponse struct {
	Error   bool          `json:"error"`
	Results []interface{} `json:"results"`
}

func (f *FofaAPI) ExtractAssets(domain string) ([]string, []string, error) {
	tmpl := utils.GetFOFAQuery()
	n := strings.Count(tmpl, "%s")
	args := make([]interface{}, n)
	for i := range args {
		args[i] = domain
	}
	query := fmt.Sprintf(tmpl, args...)
	b64 := base64.StdEncoding.EncodeToString([]byte(query))

	u := fmt.Sprintf("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=10000",
		url.QueryEscape(f.apiKey), url.QueryEscape(b64))

	resp, err := f.client.Get(u)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var fr fofaResponse
	if err := json.Unmarshal(bodyBytes, &fr); err != nil {
		return nil, nil, jsonDecodeError(resp.StatusCode, bodyBytes, err)
	}

	if fr.Error {
		return nil, nil, fmt.Errorf("fofa API returned error")
	}

	domains := make(map[string]struct{})
	ips := make(map[string]struct{})

	for _, item := range fr.Results {
		row, ok := item.([]interface{})
		if !ok || len(row) < 2 {
			continue
		}

		if ip, ok := row[1].(string); ok && ip != "" && utils.IsValidIP(ip) {
			ips[ip] = struct{}{}
		}

		if len(row) > 0 {
			if host, ok := row[0].(string); ok && host != "" {
				cleaned := utils.CleanDomain(host)
				if cleaned != "" {
					if utils.IsValidIP(cleaned) {
						ips[cleaned] = struct{}{}
					} else if utils.IsValidDomain(cleaned) {
						domains[cleaned] = struct{}{}
					}
				}
			}
		}
	}

	return mapKeys(domains), mapKeys(ips), nil
}
