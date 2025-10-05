package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"golang.org/x/net/publicsuffix"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&bunnyDNSProviderSolver{},
	)
}

// bunnyDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for Bunny.net DNS.
type bunnyDNSProviderSolver struct {
	client      *kubernetes.Clientset
	zoneCache   map[string]int64 // Shared zone cache across all requests
	zoneCacheMu sync.RWMutex
	initOnce    sync.Once
}

// bunnyDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
type bunnyDNSProviderConfig struct {
	// APIKeySecretRef is a reference to a secret containing the Bunny.net API key
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// bunnyAPIClient handles communication with Bunny.net DNS API
type bunnyAPIClient struct {
	apiKey      string
	httpClient  *http.Client
	zoneCache   *map[string]int64 // Pointer to shared zone cache
	zoneCacheMu *sync.RWMutex      // Pointer to shared mutex
}

// Bunny.net API response structures
type dnsZoneListResponse struct {
	Items []dnsZone `json:"Items"`
}

type dnsZone struct {
	ID      int64       `json:"Id"`
	Domain  string      `json:"Domain"`
	Records []dnsRecord `json:"Records"`
}

type dnsRecord struct {
	ID       int64  `json:"Id"`
	Type     int    `json:"Type"`
	Name     string `json:"Name"`
	Value    string `json:"Value"`
	TTL      int    `json:"Ttl"`
	Disabled bool   `json:"Disabled"`
}

type createRecordRequest struct {
	Type        string `json:"Type"`
	MonitorType string `json:"MonitorType"`
	TTL         int    `json:"Ttl"`
	Name        string `json:"Name"`
	Value       string `json:"Value"`
	Disabled    bool   `json:"Disabled"`
}

// Name returns the solver name
func (c *bunnyDNSProviderSolver) Name() string {
	return "bunny"
}

// createHTTPClient creates an HTTP client with proper timeouts
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// Present creates the DNS TXT record for the ACME challenge
func (c *bunnyDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	c.ensureInitialized()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	apiKey, err := c.getAPIKey(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get API key: %v", err)
	}

	client := &bunnyAPIClient{
		apiKey:      apiKey,
		httpClient:  createHTTPClient(),
		zoneCache:   &c.zoneCache,
		zoneCacheMu: &c.zoneCacheMu,
	}

	// Extract the domain from the resolved FQDN
	domain := extractDomain(ch.ResolvedFQDN)

	// Get the zone ID for this domain
	zoneID, err := client.getZoneID(domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	// Create the TXT record
	recordName := extractRecordName(ch.ResolvedFQDN, domain)
	err = client.createTXTRecord(zoneID, recordName, ch.Key)
	if err != nil {
		return fmt.Errorf("failed to create TXT record: %v", err)
	}

	return nil
}

// CleanUp removes the DNS TXT record
func (c *bunnyDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	c.ensureInitialized()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	apiKey, err := c.getAPIKey(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get API key: %v", err)
	}

	client := &bunnyAPIClient{
		apiKey:      apiKey,
		httpClient:  createHTTPClient(),
		zoneCache:   &c.zoneCache,
		zoneCacheMu: &c.zoneCacheMu,
	}

	// Extract the domain from the resolved FQDN
	domain := extractDomain(ch.ResolvedFQDN)

	// Get the zone ID for this domain
	zoneID, err := client.getZoneID(domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %v", domain, err)
	}

	// Delete the TXT record
	recordName := extractRecordName(ch.ResolvedFQDN, domain)
	err = client.deleteTXTRecord(zoneID, recordName, ch.Key)
	if err != nil {
		return fmt.Errorf("failed to delete TXT record: %v", err)
	}

	return nil
}

// Initialize sets up the webhook
func (c *bunnyDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	c.ensureInitialized()
	return nil
}

// ensureInitialized ensures the zone cache is initialized in a thread-safe manner
func (c *bunnyDNSProviderSolver) ensureInitialized() {
	c.initOnce.Do(func() {
		if c.zoneCache == nil {
			c.zoneCache = make(map[string]int64)
		}
	})
}

// loadConfig decodes the JSON configuration
func loadConfig(cfgJSON *extapi.JSON) (bunnyDNSProviderConfig, error) {
	cfg := bunnyDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, fmt.Errorf("no configuration provided")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// getAPIKey retrieves the API key from the Kubernetes secret
func (c *bunnyDNSProviderSolver) getAPIKey(cfg bunnyDNSProviderConfig, namespace string) (string, error) {
	secretName := cfg.APIKeySecretRef.Name
	secretKey := cfg.APIKeySecretRef.Key

	if secretName == "" || secretKey == "" {
		return "", fmt.Errorf("apiKeySecretRef name and key are required")
	}

	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %v", namespace, secretName, err)
	}

	apiKey, ok := secret.Data[secretKey]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", secretKey, namespace, secretName)
	}

	return string(apiKey), nil
}

// getZoneID retrieves the zone ID for a domain, using cache if available
func (c *bunnyAPIClient) getZoneID(domain string) (int64, error) {
	// Check cache first
	c.zoneCacheMu.RLock()
	if zoneID, ok := (*c.zoneCache)[domain]; ok {
		c.zoneCacheMu.RUnlock()
		return zoneID, nil
	}
	c.zoneCacheMu.RUnlock()

	// Not in cache, fetch from API with pagination
	page := 1
	perPage := 1000

	for {
		url := fmt.Sprintf("https://api.bunny.net/dnszone?page=%d&perPage=%d", page, perPage)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return 0, err
		}

		req.Header.Set("AccessKey", c.apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return 0, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return 0, fmt.Errorf("failed to list DNS zones: status %d, body: %s", resp.StatusCode, string(body))
		}

		var zoneList dnsZoneListResponse
		if err := json.NewDecoder(resp.Body).Decode(&zoneList); err != nil {
			resp.Body.Close()
			return 0, fmt.Errorf("failed to decode zone list: %v", err)
		}
		resp.Body.Close()

		// Search for the matching zone in this page
		for _, zone := range zoneList.Items {
			if strings.EqualFold(zone.Domain, domain) {
				// Cache the result
				c.zoneCacheMu.Lock()
				(*c.zoneCache)[domain] = zone.ID
				c.zoneCacheMu.Unlock()
				return zone.ID, nil
			}
		}

		// If we got fewer items than perPage, we've reached the end
		if len(zoneList.Items) < perPage {
			break
		}

		// Move to next page
		page++
	}

	return 0, fmt.Errorf("zone not found for domain: %s", domain)
}

// createTXTRecord creates a TXT record in the specified zone
func (c *bunnyAPIClient) createTXTRecord(zoneID int64, recordName, value string) error {
	record := createRecordRequest{
		Type:        "TXT",
		MonitorType: "None",
		TTL:         300,
		Name:        recordName,
		Value:       value,
		Disabled:    false,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.bunny.net/dnszone/%d/records", zoneID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create TXT record: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// deleteTXTRecord deletes a TXT record from the specified zone
func (c *bunnyAPIClient) deleteTXTRecord(zoneID int64, recordName, value string) error {
	// First, we need to get the zone details to find the record ID
	url := fmt.Sprintf("https://api.bunny.net/dnszone/%d", zoneID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get zone details: status %d, body: %s", resp.StatusCode, string(body))
	}

	var zone dnsZone
	if err := json.NewDecoder(resp.Body).Decode(&zone); err != nil {
		return fmt.Errorf("failed to decode zone details: %v", err)
	}

	// Find the TXT record with matching name and value
	// Type 3 is TXT in Bunny.net's API
	var recordID int64
	for _, record := range zone.Records {
		if record.Type == 3 && record.Name == recordName && record.Value == value {
			recordID = record.ID
			break
		}
	}

	if recordID == 0 {
		// Record not found - might have been already deleted
		return nil
	}

	// Delete the record
	deleteURL := fmt.Sprintf("https://api.bunny.net/dnszone/%d/records/%d", zoneID, recordID)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return err
	}

	deleteReq.Header.Set("AccessKey", c.apiKey)
	deleteReq.Header.Set("Accept", "application/json")

	deleteResp, err := c.httpClient.Do(deleteReq)
	if err != nil {
		return err
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusOK && deleteResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(deleteResp.Body)
		return fmt.Errorf("failed to delete TXT record: status %d, body: %s", deleteResp.StatusCode, string(body))
	}

	return nil
}

// extractDomain extracts the root domain from an FQDN
// e.g., "_acme-challenge.sub.example.com." -> "example.com"
// Handles multi-level TLDs correctly (e.g., "example.co.uk" -> "example.co.uk")
func extractDomain(fqdn string) string {
	// Remove trailing dot
	fqdn = strings.TrimSuffix(fqdn, ".")

	// Use publicsuffix to get the effective TLD+1 (handles multi-level TLDs like co.uk)
	domain, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		// Fallback to simple extraction if publicsuffix fails
		parts := strings.Split(fqdn, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return fqdn
	}

	return domain
}

// extractRecordName extracts the record name from an FQDN
// e.g., "_acme-challenge.sub.example.com." with domain "example.com" -> "_acme-challenge.sub"
func extractRecordName(fqdn, domain string) string {
	// Remove trailing dot
	fqdn = strings.TrimSuffix(fqdn, ".")
	domain = strings.TrimSuffix(domain, ".")

	// Remove the domain part
	if strings.HasSuffix(fqdn, "."+domain) {
		return strings.TrimSuffix(fqdn, "."+domain)
	}

	// If FQDN equals domain, record name is empty/@
	if fqdn == domain {
		return ""
	}

	return fqdn
}
