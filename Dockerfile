# syntax=docker/dockerfile:1

# -------------------------------------------------------------------------
# Stage 1 - build: restore + publish (Release, framework-dependent).
# -------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore in its own cached layer. AIRouterProxy.csproj references
# AiRouterProxy.Dashboard.csproj, so both csproj files must be present; restoring
# the .slnx instead would also require the test-harness projects (tests/) which are
# not shipped in the image.
COPY ["src/AiRouterProxy/AIRouterProxy.csproj", "src/AiRouterProxy/"]
COPY ["src/AiRouterProxy.Dashboard/AiRouterProxy.Dashboard.csproj", "src/AiRouterProxy.Dashboard/"]
RUN dotnet restore "src/AiRouterProxy/AIRouterProxy.csproj"

COPY . .
RUN dotnet publish "src/AiRouterProxy/AIRouterProxy.csproj" -c Release -o /app/publish \
    --self-contained false \
    -p:PublishSingleFile=false

# -------------------------------------------------------------------------
# Stage 2 - final: aspnet runtime + entrypoint, empty volumes for config/data.
# -------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# openssl: generates the self-signed TLS certificate on first start (the proxy is
#          HTTPS-only and will not start without one).
# gosu:    the entrypoint starts as root to chown the bind mounts and then drops to
#          the unprivileged "app" user (setpriv from util-linux is the fallback).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl gosu \
    && rm -rf /var/lib/apt/lists/*

# .NET 8+ base images ship a built-in non-root user "app" (UID 1654, $APP_UID), so no
# adduser/addgroup is needed. The proxy writes config (dashboard hot reload) and runtime
# data, so it must own both mount points.
RUN mkdir -p /config /data \
    && chown -R app:app /config /data

# AIROUTER_CONFIG_DIR / AIROUTER_DATA_DIR redirect the deploy layouts to the volumes
# (the env vars win over the auto-detect; the on-disk "config/" next to the exe is unused).
# ASPNETCORE_URLS and ASPNETCORE_HTTP_PORTS are blanked: the app binds its own HTTPS
# endpoint via Kestrel Listen (default 0.0.0.0:4000, cert loaded from /config). The aspnet
# base image defaults ASPNETCORE_HTTP_PORTS=8080, so both blanks are needed to keep the
# image's default port list from adding an extra plaintext HTTP listener.
ENV AIROUTER_CONFIG_DIR=/config \
    AIROUTER_DATA_DIR=/data \
    ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS= \
    ASPNETCORE_HTTP_PORTS=

VOLUME ["/config", "/data"]

# The image starts as root so the entrypoint can chown the bind mounts and create the
# self-signed certificate, then gosu drops to "app" before running the proxy.
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
