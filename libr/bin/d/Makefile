include ../../../global.mk
include ../../../config-user.mk

SDBPATH=$(call rmdblslash,$(LTOP)/../shlr/sdb/)
SDB=$(call rmdblslash,$(SDBPATH)/sdb)

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/format

all: dll/WS2_32.sdb dll/OLEAUT32.sdb

clean:
	rm -f dll/WS2_32.sdb dll/OLEAUT32.sdb

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

dll/WS2_32.sdb: dll/WS2_32.sdb.txt
	${SDB} dll/WS2_32.sdb = < dll/WS2_32.sdb.txt

dll/OLEAUT32.sdb: dll/OLEAUT32.sdb.txt
	${SDB} dll/OLEAUT32.sdb = < dll/OLEAUT32.sdb.txt

uninstall:
	rm -rf "$P"
