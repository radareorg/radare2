ARCH=$(shell uname -m)
ifeq ($(ARCH),x86_64)
ARCH=amd64
endif
