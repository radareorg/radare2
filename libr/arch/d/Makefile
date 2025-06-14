FILES=nes bf stm8
OPDIR=${DESTDIR}/$(DATADIR)/radare2/${VERSION}/platform

include ../../../config-user.mk

all:

clean:

.PHONY: all clean install install-symlink symstall uninstall

install:
	mkdir -p "${OPDIR}"
	cp -f *.r2 "${OPDIR}"

# that sed is a workaround for mingw's pwd
CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${OPDIR}"
	for a in ${FILES} ; do \
		ln -fs "${CWD}/$$a-init.r2" "${OPDIR}/$$a-init.r2" ; \
		ln -fs "${CWD}/$$a-fini.r2" "${OPDIR}/$$a-fini.r2" ; \
	done

uninstall:
	rm -rf "${OPDIR}"
