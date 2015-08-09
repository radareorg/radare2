PACKAGE_DIR=$(shell pwd)
include ./CONFIG
DEPENDS=

SUDO=fakeroot
SUDO=sudo
SUDO=

all:
	$(SUDO) rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -aRf root/* data
	rm -rf data/usr/lib/pkgconfig
	rm -rf data/usr/lib/*.a
	rm -rf data/usr/include
	${MAKE} control
	${MAKE} deb

include ../deb_hand.mak
