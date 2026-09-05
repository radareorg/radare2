include ../../config.mk

MAGICDIR=${DESTDIR}${DATADIR}/radare2/${VERSION}/magic

all: $(F_SDB)

install: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	# symstall leaves symlinks here; cp refuses to copy a file onto itself
	for a in default/* ; do readlink "$(MAGICDIR)";  if [ $$? != 0 ]; then rm -f "${MAGICDIR}/$$(basename $$a)" ; cp -f $$a "${MAGICDIR}" ; fi ; done

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	for FILE in $(shell cd default && ls) ; do \
		ln -fs "${CWD}/default/$$FILE" "$(MAGICDIR)/$$FILE" ; \
	done

.PHONY: install symstall
