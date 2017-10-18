include ../../config.mk

MAGICDIR=${DESTDIR}${DATADIR}/radare2/${VERSION}/magic

install: ${F_SDB}
	-rm -rf "$(MAGICDIR)"
	mkdir -p "$(MAGICDIR)"
	cp -f default/* "${MAGICDIR}"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	for FILE in $(shell cd default && ls) ; do \
		ln -fs "${CWD}/default/$$FILE" "$(MAGICDIR)/$$FILE" ; \
	done

.PHONY: install symstall
