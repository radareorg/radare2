PACKAGE_DIR=$(shell pwd)
include ./CONFIG
DEPENDS=

all:
	sudo rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -aRf root/* data
	${MAKE} control
	${MAKE} deb

include ../deb_hand.mak
