# ANBConnect ATOMS Simulator Demo

This repository contains only the public/demo ATOMS GraphQL simulator used for ANBConnect plugin testing.

It is intentionally separated from the full ANBConnect plugin source so Render does not need access to the private/corporate plugin repository.

## Endpoints

- `GET /health`
- `POST /graphql`

## Local run

```powershell
npm ci
$env:HOST = "0.0.0.0"
$env:PORT = "4010"
$env:GRAPHQL_PATH = "/graphql"
$env:ATOMS_SIM_REQUIRE_AUTH = "true"
$env:ATOMS_SIM_AUTH_TOKEN = "replace-with-local-token"
npm start
```

Then test:

```powershell
curl http://localhost:4010/health
```

## Render deployment

This repo includes `render.yaml` for Render Blueprint deployment.

Recommended Render environment variable:

```text
ATOMS_SIM_AUTH_TOKEN=<shared-demo-token>
```

The plugin should use:

```text
Endpoint: https://<render-service>.onrender.com/graphql
Authorization: Bearer <shared-demo-token>
```

## What is intentionally not included

- ANBConnect plugin source
- local simulator data store
- generated PKI certificates
- logs
- installable plugin ZIPs
- private Render token files
