FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
	ca-certificates \
	curl \
	file \
	gcc \
	git \
	make \
	patchelf \
	pkg-config \
	tar \
	xz-utils \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /r2
