FILES=pokered ascii ebcdic37 iso8859_1 katakana hiragana
# from imhex
FILES+=arabic_iso arabic_windows
FILES+=ascii_oem ascii_ansi jis7
FILES+=greek_iso greek_windows
FILES+=hebrew_iso hebrew_windows
FILES+=macintosh big5 iso_646
FILES+=cyrillic_iso cyrillic_windows

F_SDB=$(addsuffix .sdb,$(FILES))
# SUBPROJECTS TODO: SDB_EXE
SDB=../../../subprojects/sdb/sdb

include ../../../config-user.mk
include ../../../global.mk

R2_CHARSETS_PATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/charsets
CWD=$(shell pwd)

alle:
	$(SDB) -r $(shell pwd)

compile: $(F_SDB)

%.sdb: %.sdb.txt
	$(SDB) $@ = < $<
	$(SDB) -t -C $@
	test -f $@

clean:
	rm -f *.sdb *.c *.gperf *.o *.d

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
