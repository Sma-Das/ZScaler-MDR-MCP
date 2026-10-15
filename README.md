# Zscaler MDR MCP Server — Red Canary Alerts, Analyst Notes and Timelines

[![Go](https://img.shields.io/badge/Go-1.25.5%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![MCP](https://img.shields.io/badge/Model_Context_Protocol-MCP-6f42c1)](https://modelcontextprotocol.io/)
[![CI](https://github.com/Sma-Das/ZScaler-MDR-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Sma-Das/ZScaler-MDR-MCP/actions/workflows/ci.yml)
[![Docker pulls](https://img.shields.io/docker/pulls/smadas/zscaler-mdr-mcp?logo=docker)](https://hub.docker.com/r/smadas/zscaler-mdr-mcp)
[![Release](https://img.shields.io/github/v/release/Sma-Das/ZScaler-MDR-MCP)](https://github.com/Sma-Das/ZScaler-MDR-MCP/releases)
[![License](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](LICENSE)

A **read-only Zscaler MDR and Red Canary MCP server written in Go**. Connect an MCP-compatible AI assistant or SOC investigation workflow to current alerts, analyst notes, response summaries, and threat timelines—including content added after the initial alert notification.

Independent community project. Not affiliated with or endorsed by Zscaler or Red Canary. The repository name uses ZScaler for discoverability; product references use Zscaler MDR. Red Canary's existing tenant domains and REST API paths remain the integration surface.

## Why use this MDR MCP server?

- **Current investigation context:** fetch the timeline after the first webhook rather than relying on the original alert summary.
- **Provider-neutral tool contract:** three stable `mdr_*` tools and a small Go `Provider` interface. The implemented adapter supports Zscaler MDR / Red Canary; additional MDR vendors require their own verified adapter.
- **Read-only by construction:** no acknowledge, close, isolate, remediation, comment-write, or arbitrary-request tools.
- **Credential-safe evidence:** project selected timeline fields; omit raw events, automation definitions, webhook headers, `secure_data`, and model execution metadata.
- **Bounded retrieval:** explicit time, byte, page, entry, concurrency, and request-budget limits; repeated pages stop with a partial-result warning.
- **Portable deployment:** official MCP Go SDK, local stdio, stateless Streamable HTTP, non-root containers, and native release archives.

## Quick start with Docker

Release images use [`smadas/zscaler-mdr-mcp`](https://hub.docker.com/r/smadas/zscaler-mdr-mcp). Pin a release digest for production:

```bash
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1:3000:3000 \
  -e MDR_BASE_URL=https://example.my.redcanary.co \
  smadas/zscaler-mdr-mcp:latest
```

To build locally, set `MDR_BASE_URL` and run `docker compose up --build`. The tenant URL is fixed at startup. MCP callers cannot select another tenant or provider.

| Endpoint | Purpose |
| --- | --- |
| `http://localhost:3000/mcp` | Stateless MCP Streamable HTTP |
| `http://localhost:3000/healthz` | Liveness and build version; no upstream request |

## HTTP MCP client configuration

Store the API key in the client's environment or secret store:

```json
{
  "mcpServers": {
    "mdr": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": { "X-API-Key": "${MDR_API_KEY}" }
    }
  }
}
```

Environment substitution depends on the MCP client. Each HTTP request supplies its own provider key. The HTTP service does not use a server-wide `MDR_API_KEY` and does not treat an MCP bearer token as a provider credential. Use loopback or a controlled private network; an internet-facing deployment requires an authenticated gateway, TLS, and edge admission limits. This release does not implement OAuth.

## Local stdio

Build with `make build`, then configure an MCP launcher:

```json
{
  "mcpServers": {
    "mdr": {
      "command": "/absolute/path/to/zscaler-mdr-mcp",
      "args": ["stdio"],
      "env": {
        "MDR_BASE_URL": "https://example.my.redcanary.co",
        "MDR_API_KEY": "${MDR_API_KEY}"
      }
    }
  }
}
```

Stdio reads the provider key from the environment and writes only MCP protocol messages to stdout. Errors omit upstream bodies and credentials. Nothing stores fetched incidents on disk.

## Tools

| Tool | Arguments | Provider reads |
| --- | --- | --- |
| `mdr_list_alerts` | `page` (1–20, default 1), `limit` (1–50, default 10) | `GET /openapi/v3/detections` |
| `mdr_get_alert` | `alert_id` | `GET /openapi/v3/detections/{id}` |
| `mdr_get_alert_timeline` | `alert_id`, `max_pages` (1–3, default 1) | `GET /openapi/v3/detections/{id}/timeline` |

Numeric IDs and human IDs such as `THREAT-123` or `DEMO-123` are accepted. `redcanary:123` is also supported. Human prefixes are a convenience for the single configured tenant; they do not select tenants.

Results include `provider`, `source`, `retrieved_at`, normalized alerts or timeline entries, `partial`, and `warnings`. Timeline entries distinguish generated recommendations from analyst notes and preserve source activity timestamps. An entry's `occurred_at` may describe an older activity; it is **not** proof of when a note was published. Recommendations describe proposed actions, not completed remediation.

The default one-page read is deliberate. If the upstream advertises another page, the result is partial. Up to three pages can be requested; identical projected entries are deduplicated, and a repeated page terminates retrieval with an explicit warning. Pagination links are never followed as arbitrary URLs. Provider counts and links do not establish snapshot completeness.

## Configuration and limits

| Variable / limit | Default / ceiling | Behavior |
| --- | --- | --- |
| `MDR_PROVIDER` | `zscaler-mdr` | `redcanary` is an alias; other providers fail closed |
| `MDR_BASE_URL` | required | HTTPS `<tenant>.my.redcanary.co` origin; no path, credentials, query, or custom port |
| `MDR_API_KEY` | stdio only | Runtime secret; never put real keys in checked-in files |
| `HOST` | `127.0.0.1`; container `0.0.0.0` | Docker publishes to host loopback by default |
| `PORT` | `3000` | Valid TCP port |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Exact MCP Host header allowlist |
| Upstream timeout | 15 seconds/read | No automatic retries |
| Response size | 2 MiB/read | Oversized responses fail with a safe error |
| Timeline | 3 pages, 200 entries | Partial results retain successful earlier pages |
| Selected text | 16,000 bytes/field, 20 notes/entry | Truncated text carries a marker |
| HTTP requests | 64 KiB body, 16 KiB headers, 4 concurrent MCP requests | Server-side ceilings |
| Provider budget | 20 reads/minute and 10/second per process | Shared across HTTP callers; excess reads fail immediately |

Zscaler documents quotas per incoming IP. If several processes share an egress/NAT address, coordinate their total traffic externally; each process cannot observe the others. Provider throttling is surfaced without replaying requests. See the [official REST API guide](https://docs.redcanary.com/docs/red-canary-rest-api).

## Security model

Use a dedicated service account with the least privileged role that permits the required reads, such as Analyst Viewer. Provider permissions remain the final authorization boundary. The server only sends GET requests to locally constructed paths on the configured HTTPS tenant. It refuses redirects and does not forward caller keys to arbitrary relationship or pagination URLs.

Unknown timeline kinds retain only bounded type/ID/timestamp metadata; semantic content is restricted to recognized activity and recommendation kinds. Raw automation, native events, tool execution details, and upstream error bodies are excluded. Literal API keys are redacted from decoded upstream text. This projection reduces accidental exposure; returned analyst text is still private incident data and untrusted content. Do not publish results or treat text as instructions to change tool permissions.

No request/response payload logging, telemetry export, or external indicator enrichment is included. See [SECURITY.md](SECURITY.md).

## Add another MDR provider

Implement [`mdr.Provider`](go/internal/mdr/provider.go): `List`, `Get`, and `Timeline`. Return the normalized evidence envelope, fix the upstream origin and credentials in server configuration, enforce provider-specific limits, and add synthetic contract/security tests. Register the adapter in the startup provider switch. The MCP tool names and client-facing input shapes remain unchanged.

This extension contract does not imply out-of-the-box support for every vendor. Avoid generic arbitrary HTTP tools: vendor APIs differ in authentication, identifiers, permissions, pagination, and data sensitivity.

## Frequently asked questions

### Does this retrieve notes published after a Red Canary alert?

Yes. A fresh timeline read returns the current recognized analyst notes and response recommendations. Run it after the original notification and again when you explicitly need a newer snapshot. The service does not poll continuously or assume the original webhook contained the final analysis.

### Can I connect Claude, Cursor, VS Code, or another MCP client?

Use any client that supports MCP stdio or Streamable HTTP. The service exposes standard read-only tool annotations and both structured content and text JSON results.

### Can it close threats or reset accounts?

No. All provider calls are reads. Recommendations are returned as evidence text and are never executed.

### Is this an official Zscaler or Red Canary server?

No. This is an independent open-source integration, licensed under Apache 2.0.

## Development and releases

Go 1.25.5 or newer:

```bash
make ci
```

Tests use synthetic events and local HTTP servers. They cover projection, credential redaction, redirect refusal, ID validation, repeated-page termination, partial failures, response bounds, request budgets, and the MCP read-only contract.

Release automation verifies a stable semantic version tag belongs to `main`, runs checks, publishes multi-architecture Docker Hub images with provenance/SBOM, and produces checksummed native archives. Set repository variable `DOCKERHUB_USERNAME` and secret `DOCKERHUB_TOKEN` before pushing a release tag. No provider credentials are required in GitHub Actions. See [RELEASING.md](RELEASING.md).

Licensed under [Apache 2.0](LICENSE).
