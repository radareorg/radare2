include ../../../config-user.mk
P=${DESTDIR}${DATADIR}/radare2/${VERSION}/cons

all clean:

.PHONY: all clean install install-symlink symstall

CWD=$(shell pwd)

install: ${F_SDB}
	rm -rf "$P"
	mkdir -p "$P"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			cp -PRpf "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

symstall install-symlink:
	mkdir -p "$P"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			ln -fs "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

uninstall:
	rm -rf "$P"
