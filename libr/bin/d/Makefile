include ../../../global.mk
include ../../../config-user.mk

SDBPATH=$(LTOP)/../shlr/sdb/
SDB=$(SDBPATH)/sdb

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/format

DLLS=WS2_32 OLEAUT32 WSOCK32 MSI CSMFPAPI MSVBVM60 KERNEL32
DLLS+=ACLUI ACTIVEDS ATL BORLNDMM BROWSEUI COMCTL32 DSOUND
DLLS+=MFC42 MFC42U MSTLSAPI MSVBVM50 ODBC32 OLECLI32 OLEDLG
DLLS+=OLEPRO32 OLESVR32 SHDOCVW SHELL32 SHLWAPI UXTHEME
DLLS+=VB40032 VSSAPI WINMM
DLL_SDB=$(addsuffix .sdb,$(addprefix dll/,$(DLLS)))
#-include $(OBJS:.o=.d)

all: $(DLL_SDB)

clean:
	rm -f dll/*.sdb

.PHONY: all clean install install-symlink symstall

install: ${F_SDB}
	@echo "[i] Installing bin format files"
	rm -rf "$P"
	mkdir -p "$P"
	-cp -f * "$P" || true
	mkdir -p "$P/dll"
	cp -f dll/*.sdb "$P/dll"

CWD=$(shell pwd)
symstall install-symlink:
	mkdir -p "$P"
	for FILE in * ; do \
		if [ "$$FILE" != Makefile ]; then \
			ln -fs "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

$(DLL_SDB):
	$(SDB) $@ = < $@.txt

uninstall:
	rm -rf "$P"
