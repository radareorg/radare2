include ../../config-user.mk

ifeq ($(shell uname -m),arm64)
ARCH=arm64
else
ARCH=amd64
endif

DOCKER_IMAGE=r2docker
DOCKERFLAGS+=--privileged
DOCKERFLAGS+=--cap-add=SYS_PTRACE
DOCKERFLAGS+=--security-opt seccomp=unconfined
DOCKERFLAGS+=--security-opt apparmor=unconfined
R2PM=r2frida r2ghidra r2dec
# DOCKER_BUILDFLAGS+=--build-arg="R2_VERSION=$(R2_VERSION)"
DOCKER_BUILDFLAGS+=--build-arg="r2pm=${R2PM}"

ifneq ($(ARCH),)
DOCKER_PLATFORM+=--platform linux/$(ARCH)
endif

all:
	docker build $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE) . $(DOCKER_BUILDFLAGS)
	# docker buildx build --platform=linux/arm64 . -t radare/radare2
	docker run $(DOCKER_PLATFORM) -v $(shell pwd)/../..:/r -v /tmp:/tmp $(DOCKERFLAGS) -i -t ${DOCKER_IMAGE}

install:
	${INSTALL_SCRIPT} r2-docker.sh "${DESTDIR}${BINDIR}/r2-docker"

#pub:
# docker buildx build --push --platform=linux/arm64,linux/amd64 . -t radare/radare2
# docker buildx build --push --platform linux/amd64 --tag radare/radare2:latest .
#docker buildx build --push --platform linux/arm64,linux/amd64 --tag radare/radare2:latest .
#docker buildx build --push --platform linux/amd64,linux/arm64 --tag radare/radare2:latest .
#docker push radare/radare2:latest
