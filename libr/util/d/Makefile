FILES=pokered ascii ebcdic37 iso8859_1
F_SDB=$(addsuffix .sdb,$(FILES))
SDB=../../../shlr/sdb/sdb

include ../../../config-user.mk
include ../../../global.mk

R2_CHARSETS_PATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/charsets
CWD=$(shell pwd)

alle: $(F_SDB)

%.sdb: %.sdb.txt
	$(SDB) $@ = < $<
	$(SDB) -t -C $@
	test -f $@

clean:
	rm -f *.sdb *.c *.gperf

install:
	mkdir -p "$(R2_CHARSETS_PATH)"
	for FILE in *.sdb ; do \
		cp -f "${CWD}/$$FILE" "${R2_CHARSETS_PATH}/$$FILE" ; \
	done

uninstall:
	rm -rf "$(R2_CHARSETS_PATH)"

symstall install-symlink:
	mkdir -p "$(R2_CHARSETS_PATH)"
	for FILE in *.sdb ; do \
		ln -fs "${CWD}/$$FILE" "${R2_CHARSETS_PATH}/$$FILE" ; \
	done

.PHONY: alle clean uninstall install symstall install-symlink
