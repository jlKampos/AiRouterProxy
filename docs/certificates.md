# Certificates

[← Back to README](../README.md)

The proxy serves HTTPS on `https://localhost:4000`. The certificate is a self-signed cert trusted
only by machines that trust its CA. Recommended tool: **mkcert** (installs a local CA in Windows trust store).

## 1. Generate (on the server machine)

```powershell
# install mkcert (winget)
winget install FiloSottile.mkcert

# create and trust the local CA
mkcert -install

# generate cert + key covering the hostnames the proxy is reached by
# (run inside the folder the service reads the certs from, e.g. deploy/)
cd C:\Path\To\deploy
mkcert -key-file proxy-key.pem -cert-file proxy-cert.pem localhost winzone 192.168.1.77 127.0.0.1
```

Add every name clients will use (localhost, the machine name, LAN IP...). The files stay in the deploy
folder next to the exe - `appsettings.Server.json` must point at them (`PemCert` / `PemKey`).

## 2. Trust the cert on the client machine

- **Same machine** (typical usage): `mkcert -install` already added the CA to the Windows
  "Trusted Root Certification Authorities" store, so the browser and `curl` accept the cert
  (see the Node/Bun note below — Node does not read that store).
- **Other machines / VMs**: copy the CA file and install it in the Root store:
  ```powershell
  # CA file created by mkcert (elevated PowerShell):
  certutil -addstore Root "%USERPROFILE%\.local\share\mkcert\rootCA.pem"
  ```
  Or open `rootCA.pem`, then Certificate -> Install Certificate -> Current User -> "Trusted Root Certification Authorities".

Verification: `curl.exe --ssl-no-revoke https://localhost:4000/admin/health -H "Authorization: Bearer <LocalKey>"` should return a JSON body (`status: ok`).

## 3. Trust: browser (Windows store) vs Node/Bun (`NODE_EXTRA_CA_CERTS`)

`mkcert -install` adds the local CA to the **system trust store** (Windows "Trusted Root
Certification Authorities", macOS Keychain, `ca-certificates` on Linux where supported). The
browser, `curl` and .NET honour that store. **Node and Bun do not** — they trust only their
compiled-in CAs plus whatever `NODE_EXTRA_CA_CERTS` points at. OpenCode runs on Node/Bun, so a
cert that the browser accepts can still fail there with `DEPTH_ZERO_SELF_SIGNED_CERT`.

```powershell
# Windows - before starting OpenCode; mkcert -CAROOT prints the CA folder
$env:NODE_EXTRA_CA_CERTS = "$(mkcert -CAROOT)\rootCA.pem"
```

```bash
# Linux / macOS
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

The variable is read when the process starts, so export it **before** opening OpenCode.
After setting `NODE_EXTRA_CA_CERTS`, **restart the consumer (OpenCode/IDE)** — the variable only
applies to newly launched processes, so an instance that was already running keeps failing with
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `unable to verify the first certificate` (the mkcert leaf is
served, but its CA is not in that process). Kill the running `opencode` processes, open a new
terminal, check `echo $env:NODE_EXTRA_CA_CERTS`, then start it again.
`mkcert -CAROOT` also holds the CA private key — trust the `rootCA.pem` file, never share the
folder's key material.

**Docker:** the certificate the container serves must live in `config/` (mounted at
`/config` as `proxy-cert.pem` + `proxy-key.pem`); generating it elsewhere has no effect.
Replacing the files on the host is not enough — the container reads them only at start, so
run `docker compose restart`, then open OpenCode with `NODE_EXTRA_CA_CERTS` set. Full
walkthrough: [Docker — OpenCode / Node: DEPTH_ZERO_SELF_SIGNED_CERT](docker.md#opencode--node-depth_zero_self_signed_cert).

> `NODE_TLS_REJECT_UNAUTHORIZED=0` turns TLS verification off for the whole process — a
> debug-only escape hatch, not a fix.

## Alternative without mkcert (PFX)

```powershell
$cert = New-SelfSignedCertificate -DnsName "localhost","winzone","192.168.1.77" -CertStoreLocation Cert:\LocalMachine\My
$pwd = ConvertTo-SecureString "a-password" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath proxy-cert.pfx -Password $pwd
```

Then in `appsettings.Server.json` use `PfxPath`/`PfxPassword` instead of PEM files. Note: the client
must trust this cert's store too.

## Validity / rotation

The packaged certs expire (the current one is valid until 27/01/2029). Regenerate before that date,
then restart the service. The trusted CA stays valid.
