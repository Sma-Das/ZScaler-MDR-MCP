# Security policy

Use GitHub private vulnerability reporting for security findings. Do not open a public issue containing credentials, incident data, raw timeline output, or customer identifiers.

The trust boundary is read-only provider access. Tool inputs cannot select URLs, tenants, credentials, HTTP methods, or arbitrary query parameters. The first adapter supports only deployment-configured Zscaler MDR / Red Canary tenants. Use a read-only service account.

HTTP uses per-caller API keys on a fixed upstream origin. Restrict it to loopback/private networking or place it behind a TLS authenticated gateway with admission/rate controls. Host and Origin checks are not substitutes for authentication at the gateway. No OAuth support is claimed.

Raw timeline responses can contain automation credentials. Never log them. Only recognized, projected evidence fields are returned; errors omit upstream bodies. Tests and public examples must be synthetic. Never commit `.env`, private keys, incident dumps, or production tenant details.

Provider quotas are per egress IP. Coordinate multi-process deployments sharing NAT. The process budget and response limits are safeguards, not a replacement for provider authorization and network controls.

Release images run as UID 65534 and support a read-only filesystem with all capabilities dropped. Pin immutable image digests or verify native archives against the release `SHA256SUMS`.
