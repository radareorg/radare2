FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
    ca-certificates curl gcc make patchelf pkg-config tar xz-utils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /r2
