#!/usr/bin/env bash
# Zero-step Docker setup for AIRouterProxy (Linux).
#
# Creates config/ and data/, copies the non-secret config templates (never
# overwriting existing files), generates a trusted local TLS certificate with mkcert
# when it is installed and config/ has no cert yet (existing certs are kept) and runs
# `docker compose up -d --build`. Without mkcert the container seeds config/ from the
# image defaults and generates a self-signed TLS certificate on first start.
#
# Keys and the host port are exported ONLY when they are already in the environment or
# passed as options. Otherwise docker-compose.yml applies its own ${VAR:-default}
# (dummy keys, port 4000) and a .env keeps precedence - this script never overwrites a
# value that is already defined.
#
# Usage:
#   ./scripts/docker-setup.sh              # prepare + build + start
#   ./scripts/docker-setup.sh --skip-up    # prepare only
#   ./scripts/docker-setup.sh --upstream-key sk-... --local-key sk-... --host-port 5000
#   AIROUTER_API_KEY=sk-... LOCAL_PROXY_KEY=sk-... HOST_PORT=5000 ./scripts/docker-setup.sh
set -euo pipefail

usage() {
    cat <<'EOF'
docker-setup.sh - zero-step Docker setup for AIRouterProxy (Linux)

USAGE:
  ./scripts/docker-setup.sh [options]

OPTIONS:
  --upstream-key <key>   Upstream (AI Router) key -> AIROUTER_API_KEY  (default: unset)
  --local-key <key>      Local client/dashboard key -> LOCAL_PROXY_KEY (default: unset)
  --host-port <port>     Host port on 127.0.0.1                       (default: unset)
  --skip-up              Prepare folders/config/env only (no docker compose up)
  -h, --help             Show this help

ENVIRONMENT:
  AIROUTER_API_KEY   Upstream key; exported as-is when already set.
  LOCAL_PROXY_KEY    Local client/dashboard key; exported as-is when already set.
  HOST_PORT          Host port; exported as-is when already set.

Keys/port not provided are left to docker-compose.yml, which applies ${VAR:-default}
(dummy keys, port 4000). A .env file keeps precedence and is never overwritten here.

When mkcert is installed and config/ has no cert yet, this script runs `mkcert -install`
and generates config/proxy-cert.pem + config/proxy-key.pem BEFORE the up (existing
certs are never overwritten). It then prints the NODE_EXTRA_CA_CERTS command to run
before opening OpenCode: Node/Bun do not use the system trust store.

Without mkcert the container generates a self-signed certificate on first start and
the browser warns.
EOF
}

SKIP_UP=0
UPSTREAM_KEY=""
LOCAL_KEY=""
HOST_PORT_ARG=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-up) SKIP_UP=1; shift ;;
        --upstream-key)
            [ "$#" -ge 2 ] || { echo "Missing value for --upstream-key" >&2; usage >&2; exit 1; }
            UPSTREAM_KEY="$2"; shift 2 ;;
        --local-key)
            [ "$#" -ge 2 ] || { echo "Missing value for --local-key" >&2; usage >&2; exit 1; }
            LOCAL_KEY="$2"; shift 2 ;;
        --host-port)
            [ "$#" -ge 2 ] || { echo "Missing value for --host-port" >&2; usage >&2; exit 1; }
            HOST_PORT_ARG="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1. Folders (config is editable; data is created by the proxy too)
mkdir -p config data
echo "Folders ready: $REPO_ROOT/config, $REPO_ROOT/data"

# 2. Non-secret config templates - never overwrite an existing (edited) file
for name in appsettings.json routes.json redaction.json; do
    if [ -f "config/$name" ]; then
        echo "Kept existing config/$name"
    else
        cp "src/AiRouterProxy/Config/$name" "config/$name"
        echo "Copied config/$name"
    fi
done

# 3. Trusted local TLS certificate - only when mkcert exists AND config/ has no cert.
#    An existing cert (yours, another machine's, or one the entrypoint generated) is
#    always kept: never overwrite the user's certificate/key pair.
HAS_CERT=0
if [ -f config/proxy-cert.pem ] && [ -f config/proxy-key.pem ]; then
    HAS_CERT=1
fi
MKCERT_AVAILABLE=0
if command -v mkcert >/dev/null 2>&1; then
    MKCERT_AVAILABLE=1
fi
CERT_ACTION=none
if [ "$MKCERT_AVAILABLE" -eq 1 ] && [ "$HAS_CERT" -eq 0 ]; then
    echo "Generating a trusted local certificate with mkcert..."
    mkcert -install
    mkcert -cert-file config/proxy-cert.pem -key-file config/proxy-key.pem localhost 127.0.0.1 ::1
    CERT_ACTION=generated
    echo "trusted local cert generated with mkcert"
elif [ "$HAS_CERT" -eq 1 ]; then
    CERT_ACTION=kept
    echo "Kept existing config/proxy-cert.pem + config/proxy-key.pem"
fi

# 4. Keys + host port for Compose interpolation. Export ONLY values that already exist
#    in the environment or were passed explicitly: docker-compose.yml applies
#    ${VAR:-default} itself (dummy keys, port 4000) and a .env keeps precedence.
if [ -n "$UPSTREAM_KEY" ]; then
    export AIROUTER_API_KEY="$UPSTREAM_KEY"
    echo "Exported AIROUTER_API_KEY (from --upstream-key)"
elif [ -n "${AIROUTER_API_KEY:-}" ]; then
    export AIROUTER_API_KEY
    echo "Exported AIROUTER_API_KEY (from the environment)"
fi

if [ -n "$LOCAL_KEY" ]; then
    export LOCAL_PROXY_KEY="$LOCAL_KEY"
    echo "Exported LOCAL_PROXY_KEY (from --local-key)"
elif [ -n "${LOCAL_PROXY_KEY:-}" ]; then
    export LOCAL_PROXY_KEY
    echo "Exported LOCAL_PROXY_KEY (from the environment)"
fi

if [ -n "$HOST_PORT_ARG" ]; then
    export HOST_PORT="$HOST_PORT_ARG"
    echo "Exported HOST_PORT=$HOST_PORT (from --host-port)"
elif [ -n "${HOST_PORT:-}" ]; then
    export HOST_PORT
    echo "Exported HOST_PORT=$HOST_PORT (from the environment)"
fi

# 5. Build + start (the entrypoint seeds config, creates the cert and fixes the volumes)
if [ "$SKIP_UP" -eq 0 ]; then
    echo "Running: docker compose up -d --build"
    docker compose up -d --build
else
    echo "Skipping docker compose up (--skip-up)."
fi

# 6. Summary. Show the port Compose actually resolved (environment, .env, override).
EFFECTIVE_PORT=""
PORT_RESOLVED=0
if command -v docker >/dev/null 2>&1; then
    PORT_LINE="$(docker compose config 2>/dev/null | grep -m1 'published:' || true)"
    if [ -n "$PORT_LINE" ]; then
        EFFECTIVE_PORT="$(printf '%s\n' "$PORT_LINE" | sed -n 's/.*published: *"\?\([0-9][0-9]*\)"\?.*/\1/p')"
    fi
    if [ -n "$EFFECTIVE_PORT" ]; then
        PORT_RESOLVED=1
    fi
fi
if [ "$PORT_RESOLVED" -eq 0 ]; then
    EFFECTIVE_PORT="${HOST_PORT:-4000}"
fi

cat <<EOF

------------------------------------------------------------
 AIRouterProxy (Docker)
------------------------------------------------------------
 Proxy:     https://localhost:${EFFECTIVE_PORT}
 Dashboard: https://localhost:${EFFECTIVE_PORT}/admin/ui
EOF

if [ "$PORT_RESOLVED" -eq 0 ]; then
    cat <<'EOF'
 Port:  HOST_PORT/4000 assumed - a docker-compose.override.yml or .env can
        still publish a different port.
EOF
fi

if [ "$MKCERT_AVAILABLE" -eq 1 ]; then
    if [ "$CERT_ACTION" = "generated" ]; then
        cat <<'EOF'

 Certificate: trusted local cert generated with mkcert
             (config/proxy-cert.pem, config/proxy-key.pem).
EOF
    else
        cat <<'EOF'

 Certificate: config/proxy-cert.pem + config/proxy-key.pem (existing certs kept).
             mkcert is installed; the Node hint below points at its local CA.
EOF
    fi
    cat <<'EOF'

 OpenCode / Node: run this BEFORE opening OpenCode (Node does not use the system store):
   export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
   # then reopen your terminal (and OpenCode) - variables defined after start are not picked up
EOF
elif [ "$HAS_CERT" -eq 0 ]; then
    cat <<'EOF'

 Certificate: mkcert not found - the entrypoint will generate a SELF-SIGNED cert on
             first start. The browser warns and OpenCode/Node REJECTS it
             (DEPTH_ZERO_SELF_SIGNED_CERT). Two options:
             a) install mkcert (https://github.com/FiloSottile/mkcert) and re-run this
                script - it generates a trusted cert and prints the Node hint;
             b) for a quick test ONLY, disable TLS verification in the OpenCode process
                (never for normal use):
                  export NODE_TLS_REJECT_UNAUTHORIZED=0
EOF
else
    cat <<'EOF'

 Certificate: using the existing config/proxy-cert.pem + config/proxy-key.pem.
             Install mkcert for a trusted CA and the NODE_EXTRA_CA_CERTS hint.
EOF
fi

if [ -z "$UPSTREAM_KEY" ] && [ -z "$LOCAL_KEY" ] \
    && [ -z "${AIROUTER_API_KEY:-}" ] && [ -z "${LOCAL_PROXY_KEY:-}" ]; then
    cat <<'EOF'

 Keys: this script exported none - docker-compose.yml falls back to dummy keys
       unless AIROUTER_API_KEY/LOCAL_PROXY_KEY already exist in the environment
       or .env. Dummy is fine for a smoke test, but upstream calls return 401;
       pass --upstream-key/--local-key for real keys.
EOF
fi

cat <<'EOF'

 Logs:  docker compose logs -f
 Stop:  docker compose down
------------------------------------------------------------
EOF

# 7. Permissions hint. The entrypoint only re-owns config/ when "app" (UID 1654)
#    cannot write it; when that happens the host files become 1654:1654. If the owner
#    is ALREADY 1654 and your host user cannot write, `chown 1654:1654` is a no-op -
#    use ACLs or edit through the dashboard. Never run sudo automatically.
CONFIG_OWNER="$(stat -c %u config 2>/dev/null || echo unknown)"
if [ ! -w config ] || [ ! -w data ]; then
    echo ""
    if [ "$CONFIG_OWNER" = "1654" ]; then
        echo "WARNING: config/ or data/ is owned by UID 1654 (the container user) and your"
        echo "         host user cannot write it - 'sudo chown 1654:1654' would change nothing."
        echo "         Grant yourself ACL access instead:"
        echo "           sudo setfacl -R -m u:$(id -u):rwX config data"
        echo "         or edit the configuration through the dashboard."
    else
        echo "WARNING: config/ or data/ is not writable (owner UID: $CONFIG_OWNER)."
        echo "         The entrypoint re-owns them to UID 1654 on start; if that is not"
        echo "         enough (rootless Docker, restrictive mounts), grant ACL access:"
        echo "           sudo setfacl -R -m u:$(id -u):rwX config data"
    fi
fi
