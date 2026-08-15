---
title: "Installation"
description: "Run Zen IdP with Docker or build it from source, including image tags, volumes, permissions, and upgrades."
icon: "download"
weight: 2
---

# Installation

Zen IdP ships as OCI images on Docker Hub and GitHub Container Registry, and as a Go module you can build from source. Everything the service needs at runtime is inside the image: the binary, the embedded SQLite engine, and the static assets. There is no database server, no broker, and no frontend build.

## Image locations

The same image is published to two registries:

```text
docker.io/varavel/zen-idp:<version>
ghcr.io/varavelio/zen-idp:<version>
```

Both are multi-arch manifests covering `linux/amd64` and `linux/arm64`, so the same tag runs on an x86 server and on something like a Raspberry Pi or an ARM VPS without changes.

Version tags follow the releases, for example `0.1.0-alpha.6`. The `latest` tag only tracks stable releases and never points at a pre-release, so pinning an exact version keeps your upgrades deliberate and your rollback obvious.

## What the image expects

The image is designed so a standard `docker run` or compose file needs almost no configuration:

| Path           | Purpose                                                                                                                                                   |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/data/config` | Your YAML configuration. The default value of `ZEN_IDP_CONFIG_PATH` points here, and a directory selector reads every immediate `.yaml` and `.yml` child. |
| `/data/db`     | The SQLite state database. The default value of `ZEN_IDP_DB_PATH` points to `zen-idp.sqlite3` inside it.                                                  |

Both paths are declared as volumes. The process runs as an unprivileged user with UID and GID 65532, so on Linux the mounted directories must be writable by that user:

```console
mkdir -p config state
chown -R 65532:65532 state
```

Configuration is read-only for the service, so the `config` directory only needs to be readable. The port inside the container is 8080 and matches the listener defaults, see [Configuration](/docs/configuration/) if you change either side.

The only input the image does not provide is the root secret, which always comes from your environment or your secret manager.

## Run with Docker

```console
docker run -d \
  --name zen-idp \
  -p 8080:8080 \
  -v ./config:/data/config \
  -v ./state:/data/db \
  -e ZEN_IDP_SECRET="your root secret, at least 32 characters" \
  varavel/zen-idp:0.1.0-alpha.6
```

To check that the service is up, hit the health endpoint:

```console
curl http://localhost:8080/health
```

The image includes a container health check that runs the built-in `zen-idp health` command every 30 seconds, so `docker ps` reports the true state of the service, not just the state of the process.

<vara-alert
title="Do not expose the port directly"
description="In production the service speaks plain HTTP and expects TLS to be terminated in front of it. Publish the port to your proxy network, not to the internet, and see Operations for a reverse proxy example."
color="warning"
/>

## Run with Docker Compose

A compose file makes the deployment reproducible, which is worth it even for a single service:

```yaml
services:
  zen-idp:
    image: varavel/zen-idp:0.1.0-alpha.6
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - ./config:/data/config
      - ./state:/data/db
    environment:
      ZEN_IDP_SECRET: "${ZEN_IDP_SECRET}"
```

Put the root secret in an `.env` file next to the compose file, keep that file out of version control, and Compose loads it automatically:

```dotenv
ZEN_IDP_SECRET=your-root-secret
```

Binding to `127.0.0.1:8080` keeps the service reachable only from the host itself, which is exactly what you want when a reverse proxy on the same machine terminates TLS. If the proxy runs in another container, replace the binding with a shared network and no published port at all.

## Build from source

If you prefer to build the binary yourself, all you need is Go:

```console
git clone https://github.com/varavelio/zen-idp.git
cd zen-idp
go build -o zen-idp ./cmd/zen-idp
```

The project repository also defines a Taskfile with the same commands plus its development checks:

```console
task build
```

The resulting binary is self-contained and works anywhere the Go toolchain targets. When you run it outside Docker, the same three environment variables apply, and the paths point wherever you point them. See [Operations](/docs/operations/) for the complete runtime reference.

## Upgrades

Upgrading is replacing the image tag, with one safety habit:

1. Run `validate-config` with the new image and your current configuration. This catches schema changes before they reach your running service.
2. Change the image tag and recreate the container.
3. Confirm the health endpoint returns `ok`.

The state database carries forward. Ordinary upgrades and restarts preserve unexpired sessions, outstanding enrollment tokens, locks, and rate-limit counters, so nobody has to sign in again and nothing you revoked becomes valid again. If an upgrade ever changes the state schema, it is migrated automatically when the service starts.

<vara-alert
title="Version pinning"
description="Zen IdP is pre-1.0. Pre-release versions can change behavior between tags. Pin an exact version everywhere, upgrade one tag at a time, and validate configuration with the new image before switching traffic to it."
color="info"
/>
