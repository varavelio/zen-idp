# Use rust (debian trixie) as the base image
FROM rust:1.97.1-trixie

# Install Node.js
COPY --from=node:24-trixie /usr/local/ /usr/local/

# Set environment variables
ENV \
  DEBIAN_FRONTEND="noninteractive" \
  PIP_BREAK_SYSTEM_PACKAGES=1

RUN set -e && \
  # Update and install system dependencies
  apt-get update -qq && \
  apt-get install -yqq --no-install-recommends \
  ca-certificates build-essential wget curl zip unzip p7zip-full tzdata git tree ripgrep \
  python3 python3-pip && \
  # Install tools from npm
  npm install --global @go-task/cli@3.51.1 && \
  npm install --global dprint@0.54.0 && \
  # Git config
  git config --global --add safe.directory '*' && \
  # Cleanup
  npm cache clean --force && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Just to keep the container running
CMD ["sleep", "infinity"]
