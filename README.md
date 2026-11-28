# AiRouterProxy — Security Gateway for AI Coding Agents

*Your AI agent can read your code. It doesn't need to expose your secrets.*

Local HTTPS proxy for the AI Router with a **multi-upstream router**: a per-path route table
forwards to several OpenAI-compatible providers, each with its own key.
**Current version:** 2.8.0 ([releases](https://github.com/jlKampos/AiRouterProxy/releases)).

☕ Found this useful? [**Support the project**](https://buymeacoffee.com/jlkampos) with a coffee — every cup keeps the redaction growing.

## What it is

- **Security gateway** between your AI coding agents and the AI Router (any OpenAI-compatible
  upstream), running locally over HTTPS on port 4000.
- **Redaction, fail-closed inspection and per-client rate limiting** on every outgoing request, so
  secrets never reach the model provider.
- **Admin dashboard, admin REST API v1, detection forensics and transport/endpoint attestation**
  (v2.8.0) - all protected by the primary local key.

| At a glance | |
|---|---|
| Runtime | .NET 10 / ASP.NET Core, self-contained `win-x64` or a Linux container |
| Listens on | HTTPS `:4000` (Kestrel + TLS; self-signed cert trusted by your CA) |
| Config | `appsettings*.json`, `routes.json`, `redaction.json` - hot reload for routes/redaction/keys |
| Admin | Blazor dashboard `/admin/ui` + REST API `/admin/api/v1/*` (primary local key only) |

## Quick start (5 minutes)

**Prerequisites:** .NET 10 SDK (to build and run from source) or Docker (Linux container).

1. **Keys.** Create `src/AiRouterProxy/appsettings.Server.json` from the template
   `src/AiRouterProxy/Config/appsettings.Server.example.json` and fill `Proxy:Keys:UpstreamKey` +
   `Proxy:Keys:LocalKey` (generate the local key with `scripts\genApiKey.ps1`). Alternatively leave
   the config values empty and set the environment variables `AIROUTER_API_KEY` / `LOCAL_PROXY_KEY`.
   Details: [docs/configuration.md](docs/configuration.md).
2. **Certificate.** The proxy only speaks HTTPS. Generate a trusted local certificate with mkcert
   and place `proxy-cert.pem` / `proxy-key.pem` in `src/AiRouterProxy/` (copied to the output
   `config/` folder on build). Details: [docs/certificates.md](docs/certificates.md).
3. **Run it.** Development: `dotnet run --project src/AiRouterProxy/AIRouterProxy.csproj`.
   As an installed Windows Service: [docs/operations.md](docs/operations.md).
   In Docker: [docs/docker.md](docs/docker.md).
4. **Use it.** Open the dashboard at `https://localhost:4000/admin/ui` and log in with the primary
   local key; then point OpenCode at the proxy by copying a ready-made config from
   `opencode_configs/`. Details: [docs/opencode.md](docs/opencode.md).
5. **Verify.** With the primary local key:
   ```powershell
   curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/status -H "Authorization: Bearer <LocalKey>"
   # {"status":"ok","version":"2.8.0","routes":N,"redactionEnabled":true,...}
   ```

## Why

AiRouterProxy enforces that **secrets never leave the machine** - in personal and corporate
development environments alike. Instructions (`AGENTS.md`) and client-side permissions are layers
1 and 2; this proxy is the edge filter (layer 3) that inspects every outgoing request and masks
what slipped through: a key pasted in free text, a secret in a code block, a config dumped into a
prompt. It is provider-agnostic, so it also fits EU-resident / zero-data-retention gateway policies.

The full story, the defense-in-depth model and exactly what gets masked:
[docs/overview.md](docs/overview.md).

## Documentation

| Document | What it covers |
|---|---|
| [docs/overview.md](docs/overview.md) | Why it exists, defense in depth, what gets masked, demo, stack and the detailed repo structure |
| [docs/configuration.md](docs/configuration.md) | Every config file (`appsettings*.json`, `routes.json`, `redaction.json`), inspection, rate limiting, `/admin` access, hot reload |
| [docs/attestation.md](docs/attestation.md) | Transport / endpoint attestation (v2.8.0): observation, pins, drift, enforce modes and limitations |
| [docs/admin.md](docs/admin.md) | Local keys / `genApiKey.ps1`, the Blazor dashboard and the admin REST API v1 |
| [docs/forensics.md](docs/forensics.md) | Triaging detection forensics (metadata only: JSON path, layer, kind, fingerprint) |
| [docs/certificates.md](docs/certificates.md) | mkcert setup, trusting the CA on client machines, PFX alternative, validity/rotation |
| [docs/opencode.md](docs/opencode.md) | Ready-made `opencode.json` configs, `watcher`/`permissions`, the Anthropic route and troubleshooting |
| [docs/testing.md](docs/testing.md) | Unit, dashboard and integration harnesses (551 / 403 / 24 PASS) |
| [docs/operations.md](docs/operations.md) | Interactive menu (`proxy-menu.ps1`) and deploying/moving the installed Windows Service |
| [docs/docker.md](docs/docker.md) | Running the same binary in a Linux container (guide in Portuguese) |

## Structure

```
AiRouterProxy/
|-- src/AiRouterProxy/            # host: pipeline, detection, routing, SSE, transport, observability, admin
|-- src/AiRouterProxy.Dashboard/  # Blazor Web App served under /admin/ui
|-- tests/                        # Unit, Dashboard.Tests, Integration harnesses
|-- scripts/                      # proxy-menu.ps1, deploy-update.ps1, genApiKey.ps1
|-- docs/                         # detailed documentation (this README links into it)
|-- images/                       # screenshots used by the docs
|-- opencode_configs/             # ready-made opencode.json examples
|-- Dockerfile, docker-compose.yml
`-- AIRouterProxy.slnx, LICENSE, README.md
```

## Tests

Offline unit harness: **551 PASS**; dashboard harness: **403 PASS**; black-box integration
harness: **24 PASS** (last known run). How to run them: [docs/testing.md](docs/testing.md).

## Docker (Linux containers)

The same `AIRouterProxy` binary runs in a Linux container, with `config/` and `data/` bind-mounted
from the host (local HTTPS, admin dashboard and attestation included). It is **zero-step**:

```bash
docker compose up -d --build
```

The container generates a self-signed certificate on first start and falls back to dummy keys
(port 4000, `HOST_PORT` to change). Details and real keys: [docs/docker.md](docs/docker.md).
OpenCode/Node need `NODE_EXTRA_CA_CERTS` (see [docs/docker.md#opencode--node-depth_zero_self_signed_cert](docs/docker.md#opencode--node-depth_zero_self_signed_cert)) — set it and reopen the terminal before starting OpenCode.

## License

[MIT](LICENSE).
