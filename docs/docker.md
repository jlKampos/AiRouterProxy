# AIRouterProxy em Docker

[← Back to README](../README.md)

Corre o proxy HTTPS local (o mesmo binário do serviço Windows `AIRouterProxy`) num
container, com a configuração e os dados de runtime colocados em pastas do host.
Nada muda no comportamento: redação de segredos, rotas, rate limit, dashboard
(`/admin/ui`) e as funcionalidades Transport/Endpoint Attestation (v2.8.0) são as mesmas.

## Pré-requisitos

- Docker com suporte a `Dockerfile` e Compose v2 (`docker compose`).
- **Mais nada.** O certificado TLS é gerado automaticamente no primeiro arranque e as
  chaves têm defaults `dummy` (ver [Chaves](#chaves)). Para um certificado *trusted* no
  browser (sem aviso) recomenda-se o [`mkcert`](https://github.com/FiloSottile/mkcert) —
  é opcional.

## Estrutura de ficheiros

| Pasta | Conteúdo | Observações |
|---|---|---|
| `config/` | `routes.json`, `redaction.json`, `appsettings.json` e os certificados TLS (`proxy-cert.pem` + `proxy-key.pem`) | Montada em `/config` dentro do container. O cert é criado automaticamente se faltar |
| `data/` | Criada **automaticamente**: `endpoint-baseline.json`, `pins.json`, `audit.log`, `key-meta.json`, `backups/` | Montada em `/data` (volume) |

As detecções/forensics são **em memória** (ring buffer) — nunca gravadas em `data/`.

`config/`, `data/` e `docker-compose.override.yml` são **locais** (bind-mounts) e estão no
`.gitignore` (`/config/`, `/data/`, `/docker-compose.override.yml`): não vêm no repo e nunca
entram no build context (`.dockerignore`).

## Ficheiros incluídos

O `Dockerfile` e o `docker-compose.yml` ficam na **raiz** do repo (junto ao
`AIRouterProxy.slnx`), não em `docker/` — este guia fica em `docs/docker.md`. O
`docker/entrypoint.sh` é o entrypoint do container (cria as pastas, semeia `config/` a
partir dos defaults da imagem, ajusta os donos, gera o cert e baixa privilégios para o
user `app`).

## Quick start (zero passos)

Na raiz do repo:

```bash
docker compose up -d --build
```

Não há passos manuais: o container

1. cria `config/` e `data/` se não existirem (bind mounts);
2. **semeia** `config/` com `appsettings.json`, `routes.json` e `redaction.json` a partir
   dos defaults que já vão na imagem (`/app/config/`), apenas os que faltarem — nunca
   sobrescreve ficheiros editados. Sem este seed o proxy arrancava sem `AllowedPaths` e o
   `/v1/*` respondia `404`;
3. gera um certificado **self-signed** em `config/` se `proxy-cert.pem`/`proxy-key.pem`
   faltarem;
4. usa chaves `dummy` e a porta `4000` por omissão.

Depois abre:

- Dashboard: `https://localhost:4000/admin/ui` (o browser avisa do certificado — avançar).
- Proxy: `https://localhost:4000` (as chamadas ao upstream chegam ao provider e devolvem
  `401` com a chave dummy; `502` se o upstream estiver inacessível — já **não** `404`).

Para parar: `docker compose down`.

> O seed é feito pelo entrypoint, não pelo compose: um `config/` vazio no host fica
> preenchido no primeiro `up`. O que já existir em `config/` é sempre preservado. Os
> scripts de setup (secção [Scripts de setup](#scripts-de-setup)) copiam os mesmos JSON do
> repo antes do `up`, o que dá o mesmo resultado com o ficheiro já visível no host.

## Certificado

O entrypoint gera um cert self-signed (`CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`,
365 dias) quando não encontra `config/proxy-cert.pem` + `config/proxy-key.pem`:

```
[entrypoint] No TLS certificate in /config - generating a self-signed one...
[entrypoint] Self-signed certificate generated (the browser will warn; use mkcert for a trusted cert).
```

Self-signed: o browser mostra o aviso de certificado (avançar) e `curl -k` funciona. O
OpenCode/Node **não** aceita este cert — ver
[a secção seguinte](#opencode--node-depth_zero_self_signed_cert).

### Certificado trusted (mkcert)

Para browser sem aviso, gera o cert com o mkcert **antes** do primeiro `up` (o entrypoint
respeita ficheiros existentes):

```bash
mkcert -install
mkcert -cert-file config/proxy-cert.pem -key-file config/proxy-key.pem localhost 127.0.0.1 ::1
docker compose restart
```

Se o `config/` não for gravável, o entrypoint avisa (`mount config writable or provide the
certs`) e termina com erro — nesse caso corrige as permissões (ver
[Permissões no Linux](#permissões-no-linux)) ou fornece os PEM manualmente.

## OpenCode / Node: DEPTH_ZERO_SELF_SIGNED_CERT

O OpenCode corre sobre Node/Bun, que **não usa o store de certificados do sistema**
(Windows "Trusted Root Certification Authorities", Keychain, `ca-certificates`). Por isso o
browser (com o aviso aceite) e `curl -k` funcionam, mas o cliente TLS do Node rejeita o cert
self-signed do entrypoint com `DEPTH_ZERO_SELF_SIGNED_CERT` (por vezes
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` ou `self signed certificate in certificate chain`). Não é
um problema do proxy — é o Node a não ver a CA.

Solução: servir um cert *trusted* (mkcert) e apontar o Node para a CA local com
`NODE_EXTRA_CA_CERTS`.

```bash
# 1. cert trusted em config/ (o entrypoint respeita ficheiros existentes)
mkcert -install
mkcert -cert-file config/proxy-cert.pem -key-file config/proxy-key.pem localhost 127.0.0.1 ::1
docker compose restart      # o cert só é lido no arranque do container

# 2. no ambiente que abre o OpenCode (Linux/macOS)
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

```powershell
# Windows: o mkcert -install confia no store, mas o Node só vê a CA por esta env var
$env:NODE_EXTRA_CA_CERTS = "$(mkcert -CAROOT)\rootCA.pem"
```

O `NODE_EXTRA_CA_CERTS` tem de estar definido **antes** de abrir o OpenCode (é lido no
arranque do processo). Os scripts de setup (`scripts/docker-setup.ps1` /
`scripts/docker-setup.sh`) geram o cert com mkcert quando está instalado e `config/` ainda não
tem cert, e imprimem este comando no resumo final.

**Definir a env não chega: é obrigatório reabrir o terminal/OpenCode.** A variável só se
aplica a processos lançados **depois** de estar definida — um OpenCode já aberto (e o
servidor/daemon que o TUI usa) continua sem a CA. Persistente, definida uma vez:

```powershell
# Windows (User scope - aplica-se a terminais novos depois de reabertos)
[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', "$(mkcert -CAROOT)\rootCA.pem", 'User')
Get-Process opencode -ErrorAction SilentlyContinue | Stop-Process -Force   # mata as instâncias abertas
# abre um terminal NOVO, confirma e só então arranca:
echo $env:NODE_EXTRA_CA_CERTS
opencode
```

```bash
# Linux/macOS: na shell profile (~/.bashrc, ~/.zshrc), depois abre um terminal novo
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

Se depois do cert mkcert o erro mudar de `DEPTH_ZERO_SELF_SIGNED_CERT` para
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` (ou `unable to verify the first certificate`), o sintoma é
exatamente esse: o leaf mkcert já é servido, mas a CA (`rootCA.pem`) não está no processo
Node/Bun que está a correr — falta a env acima **e** o reinício do consumidor. Confirma com
`curl -s https://localhost:4000/admin/health`: um `401` (e não erro TLS) confirma que o cert
está bom no lado do proxy.

> `NODE_TLS_REJECT_UNAUTHORIZED=0` desativa a verificação TLS **de todo o processo** do
> OpenCode — serve só para um teste rápido, nunca para uso normal (o proxy também valida o
> TLS dos upstreams).

> O cert é **por máquina**: cada host gera o seu par com o seu próprio `mkcert -install`.
> Não copies `config/proxy-cert.pem`/`proxy-key.pem` entre máquinas e **nunca partilhes o
> `proxy-key.pem`** (é a chave privada do teu cert).

## Chaves

O `docker-compose.yml` usa defaults `dummy` para `AIROUTER_API_KEY` e `LOCAL_PROXY_KEY`:
o primeiro arranque nunca falha por interpolação e serve de smoke test. Health, dashboard
e attestation funcionam; as chamadas ao upstream devolvem `401` (esperado — a chave dummy é
rejeitada pelo provider). A local key dummy (`dummy`) é a que usas no login do dashboard.

Para chaves reais, define-as no ambiente do host, num `.env` na raiz (não versionado) ou
inline:

```bash
AIROUTER_API_KEY=... LOCAL_PROXY_KEY=... docker compose up -d
```

```powershell
$env:AIROUTER_API_KEY='...'; $env:LOCAL_PROXY_KEY='...'; docker compose up -d
```

O `.env` fica no `.gitignore` e no `.dockerignore` — as chaves nunca entram na imagem.

## Porta

O compose publica `127.0.0.1:${HOST_PORT:-4000}:4000` — a porta interna é sempre `4000`
(`Proxy__Port` no compose), a do host é configurável:

```bash
HOST_PORT=5000 docker compose up -d
```

```powershell
$env:HOST_PORT='5000'; docker compose up -d
```

Se a `4000` estiver ocupada no host (ex.: o serviço Windows do proxy já lá está), usa
`HOST_PORT`; não é preciso `docker-compose.override.yml`. O bind é só em `127.0.0.1`
(sem exposição na LAN).

## Scripts de setup

Fazem o mesmo que os passos manuais, sem interação: criam `config/`/`data/`, copiam os
templates JSON **apenas se não existirem** (nunca sobrescrevem edições) e correm
`docker compose up -d --build`. As chaves/porta só são exportadas quando as passas
explicitamente: o resto fica para o `${VAR:-default}` do compose, e um valor já definido
no ambiente ou num `.env` **não é sobrescrito**.

Windows (PowerShell):

```powershell
.\scripts\docker-setup.ps1
.\scripts\docker-setup.ps1 -UpstreamKey 'sk-real' -LocalKey 'sk-local' -HostPort 5000
.\scripts\docker-setup.ps1 -SkipUp      # só prepara pastas/config (não exporta nada)
```

Linux (bash):

```bash
chmod +x scripts/docker-setup.sh     # once (the exec bit is lost on Windows checkouts)
./scripts/docker-setup.sh
./scripts/docker-setup.sh --upstream-key sk-real --local-key sk-local --host-port 5000
AIROUTER_API_KEY=sk-real LOCAL_PROXY_KEY=sk-local HOST_PORT=5000 ./scripts/docker-setup.sh
./scripts/docker-setup.sh --skip-up     # só prepara pastas/config (não exporta nada)
```

Ambos imprimem no fim as URLs com a porta que o Compose efetivamente resolveu (lida de
`docker compose config`, logo um `.env`/override já conta), o aviso do cert self-signed e
o comando para parar.

## Permissões no Linux

O container arranca como root apenas para o entrypoint poder preparar os mounts e depois
baixa para o user `app` (UID 1654) via `gosu`. O `chown` é **condicional**:

- `/data` é sempre do container (bind mount criado pelo compose ou volume nomeado) — é
  re-ownado para `app` sem condições.
- `/config` é um bind mount do host: o entrypoint testa primeiro se `app` consegue
  escrever e **só faz `chown -R app:app /config` quando não consegue**. Se o teu user do
  host já escreve em `config/`, nada é alterado.

Quando esse chown acontece num host Linux, os ficheiros de `config/` e `data/` passam a
pertencer a **1654:1654** no host — e o teu user deixa de os poder editar diretamente.
Alternativas (por ordem de preferência):

```bash
# 1. ACLs: mantém o dono 1654 e dá-te acesso sem mudar o dono
sudo setfacl -R -m u:$(id -u):rwX config data

# 2. Editar a configuração pelo dashboard (https://localhost:4000/admin/ui),
#    que grava como o user "app"
# 3. Correr o container com o teu UID/GID (docker-compose.override.yml), sem chown:
#      services:
#        airouterproxy:
#          user: "1000:1000"
#          group_add: ["1654"]
```

`sudo chown 1654:1654 config data` **não resolve** quando o dono já é 1654 — nesse caso o
que falta é acesso do teu user, não do container. Se o dashboard não conseguir gravar (o
entrypoint imprime `WARNING: /config is not writable by 'app'`), usa o `setfacl` acima.

Se o `config/` continuar a não ser gravável depois do chown (rootless Docker, mount com
opções restritivas), o entrypoint avisa e termina a configuração sem o cert — corrige as
permissões no host com ACLs.

**SELinux** (Fedora/RHEL): um bind mount em `:z`/`:Z` é reetiquetado para o container. O
`docker-compose.yml` não usa `:z`; se o SELinux bloquear a escrita em `config/`/`data/`,
acrescenta `:z` no override (`./config:/config:z`) — evita `:Z` se a pasta for partilhada
com outros processos do host.

## Hot reload

- **Linux**: fiável — `routes.json` / `redaction.json` são
  recarregados automaticamente (file polling). Alterações feitas no dashboard são
  gravadas em `/config` (visíveis no host).
- **Windows Desktop (Docker Desktop)**: menos fiável — se uma alteração não for
  recolhida, reinicia o container (`docker compose restart`).
- `appsettings.json` e certificados exigem restart.

## O que funciona (v2.8.0)

| Área | Estado |
|---|---|
| Redação automática de segredos (4 camadas) + notice na resposta | ✔ |
| Rotas/upstreams multi + rate limit + inspeção fail-closed | ✔ |
| Dashboard `/admin/ui` (rotas, chaves, segurança, activity, settings, attestation) | ✔ |
| Detecções forensics (metadata, em memória) | ✔ |
| Transport/Endpoint Attestation: baseline, pins, probe e drift | ✔ |
| Backups `data/backups`, audit `data/audit.log` | ✔ |
| Event Log do Windows | ✘ (ver secção seguinte) |

## Event Log

O Event Log do Windows não existe no container (Linux):

- O proxy escreve para o **stdout** — `docker logs -f airouterproxy`.
- `GET /admin/logs` responde `{ count: 0, entries: [], note: "Event Log is Windows-only; use 'docker logs'." }`.
- `DELETE /admin/api/v1/logs/eventlog` regista `unavailable` no audit (não falha).
- Persiste `data/` num volume (já configurado no compose) para baseline/pins/audit
  sobreviverem a `docker compose down` — só o `-v` (não usado aqui) os apaga.

## Comandos úteis

```bash
docker compose up -d --build   # build + arranque
docker compose logs -f         # segue os logs (stdout)
docker compose restart         # reinicia (configs/certs que exigem restart)
docker compose down            # para (os volumes config/ + data/ ficam no host)
docker compose ps              # estado
docker exec -it airouterproxy sh   # shell dentro do container (debug)
```

> **Nota:** os defaults (`dummy`) do compose evitam falhas de interpolação — `logs`, `ps`
> e `down` funcionam sem exportar chaves. Para usar chaves reais basta exportá-las (ou um
> `.env` na raiz) antes de qualquer comando compose.

## Nota final (segurança)

`appsettings.Server.json` **nunca** é commitado nem publicado
(`CopyToPublishDirectory=Never` no csproj) e está excluído do build Docker —
as chaves entram **sempre** por variáveis de ambiente. Os certificados são
ficheiros do host montados em `config/` (ou gerados pelo entrypoint no primeiro arranque),
nunca copiados para a imagem.
