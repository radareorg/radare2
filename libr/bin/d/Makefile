include ../../../global.mk
include ../../../config-user.mk

SDBPATH=$(call rmdblslash,$(LTOP)/../shlr/sdb/)
SDB=$(call rmdblslash,$(SDBPATH)/sdb)

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/format

DLLS=WS2_32 OLEAUT32 WSOCK32 MSI CSMFPAPI
DLL_SDB=$(addsuffix .sdb,$(addprefix dll/,$(DLLS)))
#-include $(OBJS:.o=.d)

all: $(DLL_SDB)

clean:
	rm -f dll/*.sdb

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	rm -rf "$P"
	mkdir -p "$P"
	cp -f * "$P"
	mkdir -p "$P/dll"
	cp -f dll/*.sdb "$P"

CWD=$(shell pwd)
symstall install-symlink:
	mkdir -p "$P"
	for a in * ; do \
		if [ $$a != Makefile ]; then \
			ln -fs "${CWD}/$$a" "$P/$$a" ; \
		fi ; \
	done

$(DLL_SDB):
	$(SDB) $@ = < $@.txt

uninstall:
	rm -rf "$P"
