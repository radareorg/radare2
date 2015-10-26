PACKAGE_DIR=$(shell pwd)
include ./CONFIG
DEPENDS=

all:
	sudo rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -aRf root/* data
	rm -rf data${LIBDIR}/pkgconfig
	rm -rf data${LIBDIR}/*.a
	rm -rf data${INCLUDEDIR}
	${MAKE} control
	${MAKE} deb

include ../deb_hand.mak
