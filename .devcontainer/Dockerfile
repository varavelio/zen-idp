# Use golang (debian trixie) as the base image
FROM golang:1.26-trixie

# Install Node.js
COPY --from=node:24-trixie /usr/local/ /usr/local/

# Install golangci-lint
COPY --from=golangci/golangci-lint:v2.12.2 /usr/bin/golangci-lint /usr/local/bin/golangci-lint

# Install SQLC
COPY --from=sqlc/sqlc:1.31.1 /workspace/sqlc /usr/local/bin/sqlc

# Install Veta
COPY --from=varavel/veta:0.1.0 /usr/local/bin/veta /usr/local/bin/veta

# Set environment variables
ENV \
  DEBIAN_FRONTEND="noninteractive" \
  PIP_BREAK_SYSTEM_PACKAGES=1 \
  CGO_ENABLED=0

RUN set -e && \
  # Update and install system dependencies
  apt-get update -qq && \
  apt-get install -yqq --no-install-recommends \
  ca-certificates wget curl zip unzip p7zip-full tzdata git tree ripgrep \
  python3 python3-pip && \
  # Install tools from npm
  npm install --global @go-task/cli@3.52.0 && \
  npm install --global dprint@0.55.2 && \
  # Install goose
  curl -fsSL https://raw.githubusercontent.com/pressly/goose/v3.27.3/install.sh | sh -s v3.27.3 && \
  # Git config
  git config --global --add safe.directory '*' && \
  # Cleanup
  npm cache clean --force && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Just to keep the container running
CMD ["sleep", "infinity"]
