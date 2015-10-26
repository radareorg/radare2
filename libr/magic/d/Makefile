include ../../config.mk

MAGICDIR=${DESTDIR}${LIBDIR}/radare2/${VERSION}/magic
install: ${F_SDB}
	-rm -rf "$(MAGICDIR)"
	mkdir -p "$(MAGICDIR)"
	cp -f default/* "${MAGICDIR}"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	cd default ; for FILE in * ; do ln -fs "${CWD}/default/$$FILE" \
		"$(MAGICDIR)/$$FILE" ; done

.PHONY: install symstall
