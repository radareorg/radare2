include ../../../config-user.mk
P=${DESTDIR}${DATADIR}/radare2/${VERSION}/cons

all clean:

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	rm -rf "$P"
	mkdir -p "$P"
	cp -f * "$P"

CWD=$(shell pwd)
symstall install-symlink:
	mkdir -p "$P"
	for a in * ; do \
		if [ $$a != Makefile ]; then \
			ln -fs "${CWD}/$$a" "$P/$$a" ; \
		fi ; \
	done

uninstall:
	rm -rf "$P"
