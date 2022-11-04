ARCH=amd64
# ARCH=arm64

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
	docker run $(DOCKER_PLATFORM) -v $(shell pwd)/../..:/r $(DOCKERFLAGS) -i -t r2
