# Admin: local key, dashboard and REST API

[← Back to README](../README.md)

## Local key / `genApiKey.ps1`

`scripts\genApiKey.ps1` generates keys in OpenAI format (`sk-` + unpadded base64url, 46 chars, from a CSPRNG).

| Mode | Effect |
|---|---|
| *(no flags)* | Prints usage help and exits. |
| `-Print` | Generates a key and **prints it to the console** (nothing else). Use it to create a per-engineer key: add the printed value to `Proxy:Keys:LocalKeys` on the server. That key gets `/v1/*` but **not** `/admin/*`. |
| `-Write` | Generates a key and **writes it as the primary `LocalKey`** into the deployed `appsettings.Server.json` (backup `.bak`, `LOCAL_KEY.txt`, immediate `/v1` test). |
| `-DeployDir <path>` | Target install (used with `-Write`). Default: `<repo>\deploy`. |

```powershell
# per-engineer key: prints the key to the console - add it to Proxy:Keys:LocalKeys on the server
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Print

# rotate the primary local key (writes appsettings.Server.json + LOCAL_KEY.txt)
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write

# rotate on an existing install elsewhere
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write -DeployDir "C:\Path\To\deploy"
```

With `-Write`, the script prints the key hash (never the key itself) and stores the key in
`LOCAL_KEY.txt` for the client to copy.

## Dashboard (admin UI)

A Blazor Web App served by the proxy itself at `https://<host>:4000/admin/ui/...`, protected by
the **primary local key only** (the extra keys authenticate the proxied API but never `/admin`).
It is a *helper*: every write goes through the same config files (`config\routes.json`,
`config\redaction.json`, `config\appsettings.Server.json`) that the proxy hot-reloads, so the
proxy works fully without the dashboard and the JSON files remain the source of truth.

- **Login** (`/admin/ui/login`) - enter the primary local key once; a signed session cookie keeps
  you authenticated for 12 h. The cookie signing key is derived from the primary local key, so the
  session **survives a service restart** (deploys no longer force a re-login) but is invalidated by
  rotating the primary key; logout clears it. Keys are **write-only**: the UI and the API only ever
  see fingerprints/hashes, never the values.
  If the circuit drops, the UI rejoins automatically and reloads the page when the circuit is gone
  (at most 3 reloads per minute) instead of leaving the "Rejoining the server..." dialog stuck.
- **Routes & Keys** (`/admin/ui/routes`)
  - Route table: add/edit/delete routes (prefix, upstream, keyRef, headers, timeouts). Each row
    expands into a **headers** editor (key/value rows) and the per-route **transport** policy
    (enabled/enforce/grace/probe/TLS floor/pins/expected IPs). Saves to
    `routes.json` with hot reload; new rows come pre-filled with the proxy defaults
    (300000 ms timeout / 20971520 bytes max body).
  - Route keys (`keyRef`): each ref shows a **chip** — `set` / `not set` — plus `in use` when a
    route references it; set/rotate the secret (write-only) or delete the ref (refused while in
    use). Optional owner/purpose metadata per ref (non-secret, stored in `data/key-meta.json`).
  - Local keys: the primary is fixed as `primary (admin)`; each extra key can carry a display
    **label** (e.g. the engineer's name or the laptop it was assigned to) that replaces the
    default `extra #N` — saved via `PUT /admin/api/v1/local-keys/{hash}/label`. Labels are
    metadata (fingerprint -> name) in `data/key-meta.json`; the secret values never live there.
  - Upstream key: set/rotate the key used for the default upstream when no route matches.
- **Activity** (`/admin/ui/activity`) - per-request log. Every entry shows the **presented
  hash** (fingerprint of the key that made the request, so usage is attributable by owner
  without exposing keys); refused requests additionally show the **expected hash** (or
  `(multiple keys)` when several keys match and the presented value is ambiguous) and are
  highlighted in red.
- **Security** (`/admin/ui/security`) - redaction, inspection and rate-limit settings (the
  same knobs as `redaction.json`), with restore/rollback on failed reload. Five status cards
  (local keys, rate limit, redaction, forensics, inspection) show the **saved** state; the
  Redaction/Inspection/Forensics cards add `· unsaved` while the form differs from the file.
- **Settings** (`/admin/ui/settings`) - export / validate / import the whole config bundle
  (validation first, apply after) and reload with automatic rollback when reload fails.
- **Attestation** (`/admin/ui/attestation`) - per-route endpoint cards (observed IP, SPKI, cert
  SHA-256, issuer, TLS version/cipher/ALPN, validity), the drift feed, the policy posture and
  the destructive actions (`Accept (pin)`, `Learn now`, `Clear pins`, `Clear drift` — each
  audited and re-authenticated with the primary local key).

## Admin API (v1)

REST API under `/admin/api/v1/*`, authenticated with `Authorization: Bearer <primary local
key>` (same key as `/admin`/UI) and protected by the same rate limiter. Errors are typed JSON
(`validation_error`, `authentication_error`, `not_found`, `conflict`, `rate_limited`).

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/admin/api/v1/status` | Service status + version |
| `GET` | `/admin/api/v1/routes` | Current route table (complete: `headers` + optional `transport` section) |
| `PUT` | `/admin/api/v1/routes` | Replace the route table (omitted `headers`/`transport` sections are preserved - see below) |
| `GET` | `/admin/api/v1/keys` | Key refs (with set/in-use status) + local keys (fingerprints + labels) |
| `PUT` | `/admin/api/v1/keys/{keyRef}` | Create/ensure a keyRef declaration (no secret yet) |
| `PUT` | `/admin/api/v1/keys/{keyRef}/secret` | Set/rotate the keyRef secret (write-only) |
| `PUT` | `/admin/api/v1/keys/{keyRef}/meta` | Update owner/purpose metadata |
| `DELETE` | `/admin/api/v1/keys/{keyRef}` | Delete the keyRef (refused while in use) |
| `PUT` | `/admin/api/v1/local-keys/{hash}/label` | Set/clear the display label of an extra local key |
| `GET` | `/admin/api/v1/security` | Redaction / inspection settings |
| `PUT` | `/admin/api/v1/security` | Update redaction and/or inspection sections |
| `POST` | `/admin/api/v1/keys/lookup` | Resolve a presented hash to its owner (local key / keyRef) |
| `GET` | `/admin/api/v1/config/export` | Download the full config bundle (as attachment) |
| `POST` | `/admin/api/v1/config/validate` | Validate an import bundle without applying it |
| `POST` | `/admin/api/v1/config/import` | Apply an import bundle (backup + atomic write) |
| `POST` | `/admin/api/v1/config/reload` | Re-read config from disk; restore on failed reload |
| `DELETE` | `/admin/api/v1/logs/activity` | Clears the in-memory activity buffer (admin key required). |
| `DELETE` | `/admin/api/v1/logs/eventlog` | Clears the dedicated "AIRouterProxy" Windows Event Log (admin key required). |
| `GET` | `/admin/api/v1/detections?limit=50` | Recent detection forensics (metadata only: path/layer/kind/length/`name`/`sep`/`quote`/fingerprint; limit 1..200) |
| `DELETE` | `/admin/api/v1/detections` | Clears the in-memory detection forensics buffer (admin key required) |
| `GET` | `/admin/api/v1/attestation/endpoints` | Per-route endpoint attestation: baseline entries, drift, policy (metadata only) |
| `POST` | `/admin/api/v1/attestation/{route}/accept` | Pin the route's latest observed endpoint (SPKI) — admin key required |
| `POST` | `/admin/api/v1/attestation/{route}/learn` | Probe the upstream now and record the current endpoint — admin key required |
| `DELETE` | `/admin/api/v1/attestation/pins?routeName=` | Clear the learned pins of a route (all routes when omitted) — admin key required |
| `DELETE` | `/admin/api/v1/attestation/drift` | Clear the in-memory drift feed — admin key required |

**Route table semantics (`GET`/`PUT /admin/api/v1/routes`).** `GET` returns the complete
table - each route's static `headers` and, when configured, its `transport` section (public
metadata: SPKI fingerprint pins, expected IPs, enforce/graceDays/probeHours/tlsFloor) - so the
response can be edited and sent back as-is for a valid table. Values that are invalid but
hand-edited (`graceDays > 365`, `probeHours > 720`, a bad `enforce`/`tlsFloor`/`pins`) are
returned exactly as stored and rejected on save (see the validator). `PUT` replaces the table,
but a route whose `headers` or `transport` section is omitted (`null`) keeps the section
currently stored in `routes.json` (matched by route name); `"headers": {}` clears the stored
headers. A `keyRef` that is not declared (no entry in `Proxy:RouteKeys` and not created in the
**Keys** panel) is **not** a rejection: the save succeeds with a warning (`inactive until the
keyRef is declared in the Keys panel (Add keyRef) and a key is set`) and the route stays inactive
until the ref exists with a key - matching the startup validation, which only warns. Reserved
headers, invalid upstreams and duplicate/conflicting prefixes are still validation errors. A supplied `transport` section replaces the stored one as a whole - there is no
field-by-field merge inside it. The dashboard's **Save routes** uses the same service and the
same rules. `PUT` `/admin/api/v1/routes` is non-sensitive (routes carry no secrets), so no admin
key is needed.

`GET` projects the values the kernel actually applies: a hand-edited `graceDays: 0` is
returned as `7`, a negative `probeHours` is omitted (equivalent to `0`) and a negative/zero
`poolLifetimeMinutes` is omitted (equivalent to `null` - the kernel only applies a positive
pool lifetime), so GET/export/UI/attestation agree and a `GET` -> `PUT` round-trip of a valid
table is valid (the validator still rejects writing `graceDays` 0, a negative
`poolLifetimeMinutes` or any other invalid value). Route `headers` are returned **in clear
text**: the endpoint is admin-only (same key as `/admin/endpoints`, which does the same), route
headers never carry the proxy's upstream keys - those stay in the key store behind `keyRef` -
but they may hold static operator headers (API versions, tenant ids). A `GET` -> `PUT`
round-trip of a valid table is semantically equivalent, not byte-identical: the `PUT` may write
explicit `"headers": {}`, `graceDays` and `enforce` values that were implicit in `routes.json`.
Because the section merge is keyed by route **name**, renaming a route in the dashboard
resends the `headers`/`transport` sections that route already has - a rename never drops
them. The match ignores surrounding whitespace on both sides, so a hand-edited
`" anthropic "` still keeps its sections when the (trimmed) draft is saved. Two routes whose
names differ only in surrounding whitespace are **rejected** on save: route names must be
unique (ignoring surrounding whitespace).

In a detection row, `quote` is `"` or `'` when the matched context used that quote, `""` for a
`context` finding without quotes (and a `format` that inherits its shape from such an unquoted
`context` also gets `""`), and `null` for a layer without shape (`field`, `entropy`, or a `format`
that did not inherit a shape from an overlapping context at the same offset). `name` and `sep` are
`null` wherever `quote` is `null`.

Two dashboard operations exist only as service methods used by the UI (there is no v1 endpoint
for them): adding and removing extra local keys. The legacy `/admin/*` endpoints documented
above under [Verify your changes](configuration.md#verify-your-changes) remain available and unchanged. The
legacy aliases `DELETE /admin/activity` and `DELETE /admin/logs` now go through the same audited
service path as the v1 log endpoints (audit actions `logs.clear.activity` / `logs.clear.eventlog`),
so every clear - from the API or the dashboard - leaves the same audit trail. In the dashboard,
the **Activity** page carries a single **Logs & activity** panel: a toolbar with the entry counter
and the two destructive buttons (`Clear activity` / `Clear Event Log`), a collapsible paginated
table (25/50/100 per page) and a collapsible note explaining the hashes. Each clear asks
for confirmation and then re-authenticates with the primary local key.

The **Security** page carries the redaction/inspection settings plus a **Detection forensics**
card (off by default): the card's **Enable/Disable** button persists the change immediately (the
form checkbox only stages it - the card keeps showing the saved state until the write is
confirmed), sets the buffer capacity (10..1000) and lists the latest detections - timestamp,
request id, route, **JSON path**, layer (field/format/context/entropy), kind, **pattern** (the
`name` + `sep` + `quote` shape: `context` rows, plus `format` rows that inherited it from an
overlapping context at the same offset), mask span length and an 8-char fingerprint. The value
itself is never recorded, the buffer lives in memory only (nothing on disk, cleared on restart,
on `Clear` or when forensics is disabled) and `Clear` re-authenticates with the primary local key.
See [Triaging detection forensics](forensics.md) for how to read the table.
