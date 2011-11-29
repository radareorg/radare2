include ../../../config-user.mk
IFX=${DESTDIR}/${INCLUDEDIR}

.PHONY: all symstall install

all:

PWD=$(shell pwd)
symstall install-symlink:
	mkdir -p ${IFX}/libr
	-rm -f ${IFX}/libr/sflib
	-rm -rf ${IFX}/libr/sflib
	cd ${IFX}/libr ; ln -fs ${PWD}/sflib

install:
	mkdir -p ${IFX}/libr/sflib
	cp -rf sflib/* ${IFX}/libr/sflib
