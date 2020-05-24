include ../../../global.mk

SDBCHARSETPATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/util
CWD=$(shell pwd)

all:
	for FILE in * ; do \
		if [ "$$FILE" != Makefile && "$$FILE" != meson.build ]; then \
			cp "${CWD}/$$FILE" "${SDBCHARSETPATH}/d/$$FILE" ; \
		fi ; \
	done

install:
	for FILE in * ; do \
		if [ "$$FILE" != Makefile && "$$FILE" != meson.build ]; then \
			cp "${CWD}/$$FILE" "${SDBCHARSETPATH}/d/$$FILE" ; \
		fi ; \
	done

symstall install-symlink:
	for FILE in * ; do \
		if [ "$$FILE" != Makefile && "$$FILE" != meson.build ]; then \
			cp "${CWD}/$$FILE" "${SDBCHARSETPATH}/d/$$FILE" ; \
		fi ; \
	done

.PHONY: all install symstall