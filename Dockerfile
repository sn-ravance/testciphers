# syntax=docker/dockerfile:1
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install needed packages
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      bash \
      coreutils \
      procps \
      iputils-ping \
      nmap \
      netcat-openbsd \
      openssl \
 && rm -rf /var/lib/apt/lists/*

# Install testssl.sh from upstream
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh \
 && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
 && chmod +x /opt/testssl.sh/testssl.sh

# Working directory for the project files (mounted at runtime)
WORKDIR /work

# Default shell
ENTRYPOINT ["/bin/bash"]
