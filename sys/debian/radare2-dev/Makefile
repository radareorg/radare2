PACKAGE_DIR=$(shell pwd)
include ./CONFIG
DEPENDS=
SUDO=

all:
	$(SUDO) rm -rf control data
	${MAKE} clean
	$(MAKE) root
	mkdir -p data
	cp -aRf root/* data
	${MAKE} control
	${MAKE} deb

root:
	@echo "ERROR: Please run sys/debian.sh first" ; exit 1

include ../deb_hand.mak
