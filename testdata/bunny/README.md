# Bunny.net DNS Solver Test Configuration

This directory contains the test configuration for the Bunny.net DNS solver.

## Running Tests

To run the tests, you must set the following environment variables:

- `BUNNY_API_KEY`: Your Bunny.net API key
- `TEST_ZONE_NAME`: The DNS zone to use for testing (e.g., `example.com.`)

Example:
```bash
BUNNY_API_KEY=your-api-key-here TEST_ZONE_NAME=example.com. make test
```

The test will automatically generate:
- `api-key.yaml`: A Kubernetes secret containing your API key
- `config.json`: Configuration file referencing the secret
