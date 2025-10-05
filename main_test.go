package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// Check if required environment variables are set
	apiKey := os.Getenv("BUNNY_API_KEY")
	if apiKey == "" {
		t.Skip("BUNNY_API_KEY environment variable not set, skipping test")
	}

	if zone == "" {
		t.Skip("TEST_ZONE_NAME environment variable not set, skipping test")
	}

	// Create the secret and config files
	if err := createSecretFile(apiKey); err != nil {
		t.Fatalf("failed to create secret file: %v", err)
	}

	if err := createConfigFile(); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	fixture := acmetest.NewFixture(&bunnyDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/bunny"),
	)

	//need to uncomment and delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}

// createSecretFile generates a Kubernetes secret YAML with the Bunny.net API key
func createSecretFile(apiKey string) error {
	// Base64 encode the API key
	encodedKey := base64.StdEncoding.EncodeToString([]byte(apiKey))

	secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: bunny-credentials
type: Opaque
data:
  api-key: %s
`, encodedKey)

	secretPath := filepath.Join("testdata", "bunny", "api-key.yaml")
	return os.WriteFile(secretPath, []byte(secretYAML), 0644)
}

// createConfigFile generates the config.json file
func createConfigFile() error {
	configJSON := `{
  "apiKeySecretRef": {
    "name": "bunny-credentials",
    "key": "api-key"
  }
}
`

	configPath := filepath.Join("testdata", "bunny", "config.json")
	return os.WriteFile(configPath, []byte(configJSON), 0644)
}
