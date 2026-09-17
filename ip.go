package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP detects the machine's public IPv4 address by querying
// the given provider URLs in order. It returns the first successful result.
func GetPublicIP(providers []string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	var firstErr error
	for _, url := range providers {
		ip, err := queryPublicIP(client, url)
		if err == nil {
			return ip, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", fmt.Errorf("all public IP providers failed; first error: %w", firstErr)
}

func queryPublicIP(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Reject non-2xx responses — a 4xx/5xx body is not an IP address.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response from %s: %w", url, err)
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty response from %s", url)
	}

	// Validate that the response is a valid IPv4 address.
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("response from %s is not a valid IPv4 address: %q", url, ip)
	}

	return ip, nil
}
