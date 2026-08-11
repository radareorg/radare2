FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
	apt-get install -y --no-install-recommends \
		build-essential ca-certificates curl e2fsprogs file git gperf \
		patch pkg-config python3 qemu-user wget xz-utils \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src/dist/jslinux
CMD ["make", "USE_DOCKER=0"]
