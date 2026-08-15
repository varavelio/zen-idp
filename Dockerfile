##################
# TOOLS (DEBIAN) #
##################

# Use golang (debian) as the base image
FROM golang:1.26-trixie as tools

# Install Deno
COPY --from=denoland/deno:bin-2.9.5 /deno /usr/local/bin/deno

# Install golangci-lint
COPY --from=golangci/golangci-lint:v2.12.2 /usr/bin/golangci-lint /usr/local/bin/golangci-lint

# Install SQLC
COPY --from=sqlc/sqlc:1.31.1 /workspace/sqlc /usr/local/bin/sqlc

# Install Veta
COPY --from=varavel/veta:0.1.1 /usr/local/bin/veta /usr/local/bin/veta

# Set environment variables
ENV \
  DEBIAN_FRONTEND="noninteractive" \
  PIP_BREAK_SYSTEM_PACKAGES=1 \
  CGO_ENABLED=0 \
  DENO_INSTALL_ROOT=/usr/local

RUN set -e && \
  # Install system dependencies
  apt-get update -qq && \
  apt-get install -yqq --no-install-recommends \
  ca-certificates wget curl zip unzip p7zip-full tzdata git tree ripgrep \
  python3 python3-pip && \
  rm -rf /var/lib/apt/lists/* && \
  # Install tools from npm
  deno install --global --allow-all --allow-scripts --quiet npm:@go-task/cli@3.52.0 && \
  deno install --global --allow-all --allow-scripts --quiet npm:dprint@0.55.2 && \
  deno run --allow-all npm:playwright@1.62.1 install --with-deps --no-progress chromium && \
  # Install goose
  curl -fsSL https://raw.githubusercontent.com/pressly/goose/v3.27.3/install.sh | sh -s v3.27.3 && \
  # Install Tailwind CSS standalone binary
  ARCH=$(uname -m) && \
  case "${ARCH}" in \
    x86_64)  TAILWIND_ARCH="x64" ;; \
    aarch64) TAILWIND_ARCH="arm64" ;; \
    *) echo "Arch not supported: ${ARCH}" && exit 1 ;; \
  esac && \
  curl -fsSL -o /usr/local/bin/tailwindcss "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-${TAILWIND_ARCH}" && \
  chmod +x /usr/local/bin/tailwindcss && \
  # Git config
  git config --global --add safe.directory '*'

WORKDIR /workspaces/zen-idp

################
# DEVCONTAINER #
################

FROM tools AS devcontainer

CMD ["sleep", "infinity"]

###########
# BUILDER #
###########

FROM tools AS builder

COPY Taskfile.yml go.mod go.sum ./
COPY scripts/ ./scripts/
RUN task deps

COPY . .
RUN task build

#######################
# PRODUCTION (DEBIAN) #
#######################

FROM debian:trixie-slim AS production

ENV \
    DEBIAN_FRONTEND="noninteractive" \
    ZEN_IDP_CONFIG_PATH="/data/config" \
    ZEN_IDP_DB_PATH="/data/db/zen-idp.sqlite3"

RUN \
    # Install system dependencies
    apt-get update -qq && \
    apt-get install -yqq --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    # Create group and user
    groupadd -g 65532 nonroot && \
    useradd -u 65532 -g nonroot -m -s /bin/sh nonroot && \
    # Create data directories
    mkdir -p /data/config /data/db && \
    chown -R nonroot:nonroot /data

WORKDIR /data

COPY --from=builder --chown=nonroot:nonroot /workspaces/zen-idp/dist/zen-idp /usr/local/bin/zen-idp

USER nonroot

EXPOSE 8080

VOLUME ["/data/config", "/data/db"]

ENTRYPOINT ["/usr/local/bin/zen-idp"]

CMD ["serve"]
