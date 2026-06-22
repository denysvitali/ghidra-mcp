package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
)

// ScanTCPForProject probes [DefaultTCPPort, DefaultTCPPort+TCPPortScanRange)
// on 127.0.0.1, querying /mcp/instance_info on each. Returns the first URL
// whose `project` field matches (exact wins, substring fallback).
//
// Mirrors bridge_mcp_ghidra.py:_scan_tcp_for_project (lines 534-580).
func ScanTCPForProject(ctx context.Context, project string) (string, error) {
	if project == "" {
		return "", fmt.Errorf("empty project")
	}

	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	type result struct {
		URL   string
		Info  InstanceInfo
		Exact bool
	}

	var substringHit *result
	for offset := 0; offset < config.TCPPortScanRange; offset++ {
		port := config.DefaultTCPPort + offset
		url := fmt.Sprintf("http://127.0.0.1:%d", port)
		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		info, err := probeInstanceInfo(probeCtx, client, url)
		cancel()
		if err != nil {
			continue // port not listening — move on
		}
		// Unwrap {"data": {...}} envelope if present.
		actual := info.Project
		if actual == "" {
			actual = info.CurrentProgram
		}
		if actual == project {
			return url, nil // exact match — done
		}
		if substringHit == nil && strings.Contains(actual, project) {
			substringHit = &result{URL: url, Info: info}
		}
	}
	if substringHit != nil {
		return substringHit.URL, nil
	}
	return "", fmt.Errorf("no project %q found on TCP scan range", project)
}

// probeInstanceInfo fetches /mcp/instance_info from baseURL and unwraps
// {"data": {...}} envelopes (some endpoints wrap their payload).
func probeInstanceInfo(ctx context.Context, client *http.Client, baseURL string) (InstanceInfo, error) {
	var info InstanceInfo
	url := strings.TrimRight(baseURL, "/") + "/mcp/instance_info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Decode into a generic envelope first so we can unwrap {data: ...}.
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return info, err
	}
	if data, ok := raw["data"].(map[string]any); ok {
		raw = data
	}
	// Re-marshal + unmarshal into our typed struct.
	buf, _ := json.Marshal(raw)
	if err := json.Unmarshal(buf, &info); err != nil {
		return info, err
	}
	return info, nil
}
