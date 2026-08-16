---
title: "Installation"
description: "Install Zen IdP with Docker, the shell and PowerShell installers, Homebrew, prebuilt binaries, or build it from source."
icon: "download"
weight: 2
---

# Installation

Zen IdP ships as OCI images on [Docker Hub](https://hub.docker.com/r/varavel/zen-idp) and [GitHub Container Registry](https://github.com/varavelio/zen-idp/pkgs/container/zen-idp), as prebuilt binaries for Linux, macOS, and Windows installed with a one-line command, and as a Go module you can build from source. Everything the service needs at runtime is inside the single executable: the embedded SQLite engine and the static assets. There is no database server, no broker, and no frontend build.

Pick the flavor that fits your deployment:

- **Docker** is the quickest path to a reproducible deployment, and the one this guide defaults to.
- **The binary** is self-contained and works anywhere the Go toolchain targets, from a VPS to a Raspberry Pi.

## Install with the shell installer

On Linux and macOS, the installer downloads the right binary for your platform, verifies its SHA-256 checksum, and installs it into `/usr/local/bin`:

```console
curl -fsSL https://get.varavel.com/zen-idp | sh
```

Verify the installation with `zen-idp help`, which prints the command usage.

The installer accepts a few options through environment variables:

```console
# Install a specific version
curl -fsSL https://get.varavel.com/zen-idp | VERSION=vx.x.x sh

# Install into a user directory, without sudo
curl -fsSL https://get.varavel.com/zen-idp | INSTALL_DIR=$HOME/.local/bin sh

# Suppress all output
curl -fsSL https://get.varavel.com/zen-idp | QUIET=true sh
```

When `VERSION` is not set, the installer resolves the latest release. If the target directory is not writable and a terminal is available, the installer falls back to `sudo`; point `INSTALL_DIR` somewhere writable to avoid that entirely.

## Install with Homebrew

On macOS or Linux with Homebrew, install the formula from the Varavel tap:

```console
brew install varavelio/tap/zen-idp
```

Upgrading follows the usual Homebrew flow:

```console
brew update && brew upgrade zen-idp
```

Stable releases also publish a pinned versioned formula, so you can hold an exact version with `brew install varavelio/tap/zen-idp@0.1.0` style commands when you need to.

## Install on Windows

The PowerShell installer downloads the Windows binary, verifies its SHA-256 checksum, installs it into your local programs directory, and adds it to your user `PATH`:

```powershell
irm https://get.varavel.com/zen-idp.ps1 | iex
```

Verify the installation by opening a new terminal and running `zen-idp help`.

The installer accepts the same `VERSION`, `INSTALL_DIR`, and `QUIET` options as the shell installer, set as environment variables before the command. If your execution policy blocks the one-liner, run it with an explicit bypass:

```powershell
powershell -ExecutionPolicy ByPass -Command "irm https://get.varavel.com/zen-idp.ps1 | iex"
```

## Download the binaries directly

Every release publishes prebuilt archives for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64`, plus `checksums.txt` and `manifest.json`:

```text
https://github.com/varavelio/zen-idp/releases
```

Each archive contains the binary, the readme, and the license. Verify a download against the release checksums before trusting it:

```console
sha256sum --check checksums.txt --ignore-missing
```

## Run with Docker

### Image locations

The same image is published to two registries:

```text
docker.io/varavel/zen-idp:<version>
ghcr.io/varavelio/zen-idp:<version>
```

Both are multi-arch manifests covering `linux/amd64` and `linux/arm64`, so the same tag runs on an x86 server and on something like a Raspberry Pi or an ARM VPS without changes.

Version tags follow the releases, for example `x.x.x`. The `latest` tag only tracks stable releases and never points at a pre-release, so pinning an exact version keeps your upgrades deliberate and your rollback obvious.

### What the image expects

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

### Run the container

```console
docker run -d \
  --name zen-idp \
  -p 8080:8080 \
  -v ./config:/data/config \
  -v ./state:/data/db \
  -e ZEN_IDP_SECRET="your root secret, at least 32 characters" \
  varavel/zen-idp
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

### Run with Docker Compose

A compose file makes the deployment reproducible, which is worth it even for a single service:

```yaml
services:
  zen-idp:
    image: varavel/zen-idp:x.x.x # Pin your version
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

## Run the binary outside Docker

The installed binary is the same self-contained executable the image runs, so the same rules apply with one difference: there are no image-provided defaults. The three environment variables point wherever you want them:

```dotenv
ZEN_IDP_CONFIG_PATH=/etc/zen-idp/config
ZEN_IDP_SECRET=your-root-secret
ZEN_IDP_DB_PATH=/var/lib/zen-idp/zen-idp.sqlite3
```

Validate your configuration, then start the service:

```console
zen-idp validate-config
zen-idp serve
```

<vara-alert
title="One directory per deployment"
description="Keep the configuration, the SQLite file, and any env files in a directory dedicated to the deployment, with permissions limited to the service user. The state file is disposable, but sessions and active enrollment tokens live in it."
color="info"
/>

Because the binary serves plain HTTP, terminate TLS at a reverse proxy, CDN, or load balancer in front of it, exactly as with the container. See [Operations](/docs/operations/) for a complete reverse proxy example and the runtime reference.

## Build from source

If you prefer to build the binary yourself, all you need is Go:

```console
git clone https://github.com/varavelio/zen-idp.git
cd zen-idp
go build -o zen-idp ./cmd/zen-idp
```

The project repository also defines a Taskfile with the same commands plus its development checks. Use the production task to get the same optimized binary the official artifacts ship:

```console
task build:prod
```

## Upgrades

Upgrading is replacing the image tag or the binary, with one safety habit:

1. Run `validate-config` with the new version and your current configuration. This catches schema changes before they reach your running service.
2. Replace the image tag and recreate the container, or replace the binary and restart the service.
3. Confirm the health endpoint returns `ok`.

The state database carries forward. Ordinary upgrades and restarts preserve unexpired sessions, outstanding enrollment tokens, locks, and rate-limit counters, so nobody has to sign in again and nothing you revoked becomes valid again. If an upgrade ever changes the state schema, it is migrated automatically when the service starts.
