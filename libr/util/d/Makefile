FILES=pokered ascii
F_SDB=$(addsuffix .sdb,$(FILES))
SDB=../../../shlr/sdb/sdb

include ../../../config-user.mk
include ../../../global.mk

R2_CHARSETS_PATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/charsets
CWD=$(shell pwd)

alle: $(F_SDB)

%.sdb: %.sdb.txt
	${SDB} $@ = < $<
	test -f $@

install:
	mkdir -p "$(R2_CHARSETS_PATH)"
	for FILE in *.sdb ; do \
		cp "${CWD}/$$FILE" "${R2_CHARSETS_PATH}/$$FILE" ; \
	done

uninstall:
	rm -rf "$(R2_CHARSETS_PATH)"

symstall install-symlink:
	mkdir -p "$(R2_CHARSETS_PATH)"
	for FILE in *.sdb ; do \
		ln -fs "${CWD}/$$FILE" "${R2_CHARSETS_PATH}/$$FILE" ; \
	done

.PHONY: all install symstall
