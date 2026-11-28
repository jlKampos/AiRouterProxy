#!/bin/sh
# AIRouterProxy container entrypoint.
#
# Zero-step startup:
#   1. creates /config and /data (bind mounts may start empty);
#   2. seeds /config from the image defaults (/app/config) - only the files that are
#      missing, never overwriting edits - so the proxy is functional on the very first
#      `up` (routes/redaction/appsettings make /v1/* reach the upstream instead of 404);
#   3. gives /data to "app" (always container-owned) and gives /config to "app" only
#      when it is not already writable - on a native Linux host that makes the host
#      files belong to UID 1654 (see docs/docker.md);
#   4. generates a self-signed TLS certificate on first run (the proxy only speaks
#      HTTPS and refuses to start without one);
#   5. checks that /config is writable (dashboard saves / cert rotation);
#   6. drops privileges from root to "app" and execs the proxy.
#
# umask 077 keeps everything created here (seeded config, cert/key) and everything the
# proxy writes later in /config and /data private to the owner (0600 files, 0700 dirs).
# The proxy runs as "app", which owns those files, so it can still read/write them.
#
# The container is deliberately started as root (no USER in the Dockerfile) so the
# chown + certificate generation work on any host; gosu/setpriv immediately drops
# to the unprivileged user before the .NET process runs.
set -e

umask 077

CONFIG_DIR="${AIROUTER_CONFIG_DIR:-/config}"
DATA_DIR="${AIROUTER_DATA_DIR:-/data}"
APP_USER="${AIROUTER_APP_USER:-app}"
APP_UID="${AIROUTER_APP_UID:-1654}"
# Publish output of the Dockerfile: the non-secret defaults copied by the csproj
# (Config/appsettings.json, Config/routes.json, Config/redaction.json -> /app/config).
IMAGE_CONFIG_DIR="${AIROUTER_IMAGE_CONFIG_DIR:-/app/config}"

mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# Resolve the privilege-drop helper once. gosu ships in the image; setpriv
# (util-linux) is the fallback if the package layout ever changes.
PRIV_BIN=""
if [ "$(id -u)" = "0" ]; then
    if command -v gosu >/dev/null 2>&1; then
        PRIV_BIN="$(command -v gosu)"
    elif [ -x /usr/sbin/gosu ]; then
        PRIV_BIN="/usr/sbin/gosu"
    elif [ -x /usr/bin/gosu ]; then
        PRIV_BIN="/usr/bin/gosu"
    else
        PRIV_BIN=""
    fi
fi

# Run a command as the runtime user (used for the writability probes).
run_as_app() {
    if [ "$(id -u)" != "0" ]; then
        "$@"
    elif [ -n "$PRIV_BIN" ]; then
        "$PRIV_BIN" "$APP_USER" "$@"
    else
        setpriv --reuid="$APP_UID" --regid="$APP_UID" --init-groups "$@"
    fi
}

# Can "app" create a file in CONFIG_DIR? Root can always write, so the probe must run
# as the runtime user - a root-only check would hide a broken bind mount (dashboard
# saves and certificate rotation would fail at runtime).
config_writable_as_app() {
    if run_as_app sh -c 'touch "$1"' sh "$CONFIG_DIR/.write-test" 2>/dev/null; then
        rm -f "$CONFIG_DIR/.write-test" 2>/dev/null || true
        return 0
    fi
    return 1
}

# /data is always container-owned (created here or a named volume): re-owning it never
# surprises a host user, so it is unconditional and best-effort.
chown -R app:app "$DATA_DIR" 2>/dev/null || true

# Seed the non-secret defaults so the first `up` is functional: without appsettings.json
# and routes.json the proxy starts from empty defaults and /v1/* answers 404 instead of
# reaching the upstream. Existing (edited) files are never touched.
for name in appsettings.json routes.json redaction.json; do
    if [ -f "$CONFIG_DIR/$name" ] || [ ! -f "$IMAGE_CONFIG_DIR/$name" ]; then
        continue
    fi
    if cp -n "$IMAGE_CONFIG_DIR/$name" "$CONFIG_DIR/$name" 2>/dev/null; then
        # Created by root with umask 077: hand it to the runtime user, owner-only.
        chown app:app "$CONFIG_DIR/$name" 2>/dev/null || true
        chmod 600 "$CONFIG_DIR/$name" 2>/dev/null || true
        echo "[entrypoint] seeded $name from the image defaults"
    fi
done

# /config is a host bind mount: only re-own it when "app" really cannot write, so a
# native Linux host is not silently changed on every start. When the chown is needed,
# the host files end up owned by UID 1654 - docs/docker.md lists the alternatives
# (setfacl, edit through the dashboard, or user:/group_add in docker-compose.override.yml).
if [ "$(id -u)" = "0" ] && ! config_writable_as_app; then
    echo "[entrypoint] $CONFIG_DIR is not writable by '$APP_USER' - re-owning it to UID $APP_UID..."
    chown -R app:app "$CONFIG_DIR" 2>/dev/null || true
fi

CERT_FILE="$CONFIG_DIR/proxy-cert.pem"
KEY_FILE="$CONFIG_DIR/proxy-key.pem"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "[entrypoint] No TLS certificate in $CONFIG_DIR - generating a self-signed one..."
    if ! openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"; then
        echo "[entrypoint] ERROR: could not generate the certificate in $CONFIG_DIR." >&2
        echo "[entrypoint] Mount config writable or provide the certs (proxy-cert.pem + proxy-key.pem)." >&2
        exit 1
    fi
    # openssl writes the key as root-only (umask 077); hand both files to the runtime user.
    chown app:app "$CERT_FILE" "$KEY_FILE" 2>/dev/null || true
    echo "[entrypoint] Self-signed certificate generated (the browser will warn; use mkcert for a trusted cert)."
fi

# Final check (after the optional chown): still not writable means the dashboard cannot
# save and cert rotation will fail. Point at ACLs instead of a no-op chown.
if ! config_writable_as_app; then
    echo "[entrypoint] WARNING: $CONFIG_DIR is not writable by '$APP_USER'." >&2
    echo "[entrypoint] WARNING: dashboard saves and certificate rotation will fail." >&2
    echo "[entrypoint] WARNING: on a Linux host use ACLs: sudo setfacl -R -m u:\$(id -u):rwX config data" >&2
    echo "[entrypoint] WARNING: (or edit the config through the dashboard / with sudo)." >&2
fi

# Drop from root to the unprivileged app user and exec the proxy (PID 1).
if [ "$(id -u)" != "0" ]; then
    exec dotnet AIRouterProxy.dll
fi

if [ -n "$PRIV_BIN" ]; then
    exec "$PRIV_BIN" "$APP_USER" dotnet AIRouterProxy.dll
fi

# Fallback: util-linux setpriv (present in the aspnet base image).
exec setpriv --reuid="$APP_UID" --regid="$APP_UID" --init-groups dotnet AIRouterProxy.dll
