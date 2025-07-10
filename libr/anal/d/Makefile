include ../../../global.mk

include $(TOP)/config-user.mk
HOST_CC?=gcc

FCNSIGNPATH=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/fcnsign

all: $(SDB) types-windows.sdb.txt
	$(SDB) -r .

linux-x86-32.sdb: linux-x86-32

%.sdb:%.sdb.txt $(EXTRA_FILES)

types-windows.sdb.txt:
	cat windows/*.txt > types-windows.sdb.txt

clean:
	rm -f types-windows.sdb.txt
	rm -f *.sdb *.c

$(SDB):
	@echo "Cannot find ${SDB}"
	@false

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	rm -rf "${FCNSIGNPATH}"
	mkdir -p "${FCNSIGNPATH}"
	cp -f *.sdb "${FCNSIGNPATH}"

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	cd ../../.. && mkdir -p "${FCNSIGNPATH}" && \
	for FILE in $(shell cd $(TOP)/libr/anal/d ; ls *.sdb); do \
		ln -fs "$(CWD)/$$FILE" "$(FCNSIGNPATH)/$$FILE" ; \
	done

uninstall:
	rm -rf "${FCNSIGNPATH}"
