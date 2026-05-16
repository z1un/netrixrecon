package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type CrtShAPI struct {
	client *http.Client
}

func NewCrtShAPI() *CrtShAPI {
	return &CrtShAPI{client: newHTTPClient()}
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func (c *CrtShAPI) ExtractAssets(domain string) ([]string, []string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var entries []crtShEntry
	if err := json.Unmarshal(bodyBytes, &entries); err != nil {
		return nil, nil, jsonDecodeError(resp.StatusCode, bodyBytes, err)
	}

	domains := make(map[string]struct{})
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" {
				domains[name] = struct{}{}
			}
		}
	}
	return mapKeys(domains), nil, nil
}
