include ../../config.mk

MAGICDIR=${DESTDIR}${DATADIR}/radare2/${VERSION}/magic

all: $(F_SDB)

install: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	for a in default/* ; do readlink "$(MAGICDIR)";  if [ $$? != 0 ]; then cp -f $$a "${MAGICDIR}" ; fi ; done

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	for FILE in $(shell cd default && ls) ; do \
		ln -fs "${CWD}/default/$$FILE" "$(MAGICDIR)/$$FILE" ; \
	done

.PHONY: install symstall
