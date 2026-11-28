# Transport & endpoint attestation (v2.8.0)

[← Back to README](../README.md)

The proxy records **who actually answered each TLS connection**, per route, and can pin that
identity. Built in two phases:

- **Observe** — every request that flows through a route with an active `transport` policy
  records TLS metadata of the endpoint that answered: the **observed IP:port**, the **SPKI
  fingerprint** (SHA-256 of the server's SubjectPublicKeyInfo — the value used for pinning),
  the **cert SHA-256**, the **issuer**, the **TLS version**, the **cipher suite** and the
  **ALPN**. Nothing else — never request/response payloads, never keys. Recent observations
  live in memory; up to 8 persisted endpoints per route land in `data/endpoint-baseline.json`.
- **Pin & enforce** — per-route policy in `routes.json` (`Proxy:Routes[].Transport`):
  - `pins`: SPKI fingerprints configured to always pass;
  - **learned pins** (`data/pins.json`): when you **accept** the current endpoint (dashboard
    or admin API) it stops tripping drift — effective pins = union of both, max 5 per route;
  - `tlsFloor` / `expectedIps`: extra identity constraints (TLS floor version, allowed IPs);
  - `graceDays`: how long a new-but-valid endpoint may drift before it counts as a violation;
  - `enforce: "observe" | "warn" | "block"` — `warn` tags responses with the header
    `X-AIRouterProxy-Attestation: route:severity`; `block` rejects with **HTTP 526** plus the
    same header (`...: block`);
  - `probeHours`: optional periodic **probes** — a plain TCP+TLS connect (no request is sent)
    that refreshes the baseline and the drift feed without waiting for real traffic.

The **Attestation** dashboard page (`/admin/ui/attestation`) and the admin API expose the
baseline, the drift feed and the per-route policy, with `Learn now` / `Accept (pin)` / `Clear
pins` / `Clear drift` actions — every write is audited and requires the primary local key.

## Limitations (read before relying on it)

1. **It cannot see the physical path of the packets.** TCP/IP does not expose the route
   packets take — there is no "route tracing". The proxy sees only the IP that answered at
   TLS-termination time (usually a CDN edge), not the path to it.
2. **It does NOT detect internal provider re-forwarding.** Re-forwarding happens *after* TLS
   termination, inside the provider: from the proxy's point of view the connection lands on a
   perfectly valid endpoint. An OpenRouter-style "your prompt was forwarded to an undeclared
   model" incident is **invisible at the transport level**.
3. **The baseline is TOFU** (trust on first use): the first observed endpoint is what the
   baseline learns — an attacker present at that moment would be trusted.
4. **Certificate / CDN rotation** looks like drift. Mitigated with multi-pin (configured +
   learned), the `graceDays` window and an explicit `accept`.
