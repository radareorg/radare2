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

ifneq ($(ARCH),)
DOCKER_PLATFORM+=--platform linux/$(ARCH)
endif

all:
	docker build $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE) .
	docker run $(DOCKER_PLATFORM) -v $(shell pwd)/../..:/r -v /tmp:/tmp $(DOCKERFLAGS) -i -t ${DOCKER_IMAGE}
