# Bunny.net Webhook for Cert-Manager

This is a webhook solver for [cert-manager](https://cert-manager.io) that allows you to use [Bunny.net DNS](https://bunny.net) for DNS01 ACME challenges.

## Features

- Automatic zone detection - no need to specify zone IDs
- Zone ID caching for improved performance
- Secure API key storage using Kubernetes secrets

## Installation

### Prerequisites

- Kubernetes cluster with cert-manager installed
- Bunny.net account with DNS zones configured
- Bunny.net API key

### Install the webhook

```bash
helm install bunny-webhook ./deploy/bunny-webhook \
  --namespace cert-manager
```

### Create a secret with your Bunny.net API key

```bash
kubectl create secret generic bunny-credentials \
  --from-literal=api-key=YOUR_BUNNY_API_KEY \
  --namespace cert-manager
```

## Usage

### Create an Issuer

Create a cert-manager `Issuer` or `ClusterIssuer` that uses the Bunny.net webhook:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: letsencrypt-bunny
  namespace: default
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-bunny-account-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.bunny.net
          solverName: bunny
          config:
            apiKeySecretRef:
              name: bunny-credentials
              key: api-key
```

### Request a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: letsencrypt-bunny
  dnsNames:
  - example.com
  - '*.example.com'
```

## Configuration

The webhook accepts the following configuration:

- `apiKeySecretRef`: Reference to a Kubernetes secret containing your Bunny.net API key
  - `name`: Name of the secret
  - `key`: Key within the secret that contains the API key

The webhook will automatically:
1. Look up your Bunny.net DNS zones
2. Find the appropriate zone for the domain being validated
3. Create the required TXT record for ACME validation
4. Clean up the TXT record after validation

## Test

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite.

```bash
TEST_ZONE_NAME=example.com. make test
```

You'll need to configure the test environment with your Bunny.net credentials for the tests to pass.

### Building

Build the webhook container:

```bash
make build
```

## How it works

The webhook implements the cert-manager DNS01 challenge solver interface:

1. **Zone Detection**: When a certificate is requested, the webhook queries the Bunny.net API to list all your DNS zones and finds the one matching your domain
2. **Zone Caching**: Zone IDs are cached in memory to reduce API calls
3. **Record Creation**: Creates a TXT record with the ACME challenge token
4. **Validation**: cert-manager validates the challenge by checking the DNS record
5. **Cleanup**: After validation, the webhook deletes the TXT record

## License

See [LICENSE](LICENSE) file.

## Credits

This webhook is based on the [cert-manager webhook template](https://github.com/cert-manager/webhook-example).
