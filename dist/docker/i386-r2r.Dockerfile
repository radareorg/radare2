FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		bison \
		build-essential \
		ca-certificates \
		fakeroot \
		file \
		flex \
		git \
		gperf \
		libcapstone-dev \
		liblz4-dev \
		libmagic-dev \
		libssl-dev \
		libuv1-dev \
		libxxhash-dev \
		libzstd-dev \
		libzip-dev \
		pkg-config \
		python3 \
		python3-pip \
		wget \
		xz-utils && \
	python3 -m pip install --break-system-packages --no-cache-dir r2pipe && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /src

CMD ["/bin/sh"]
