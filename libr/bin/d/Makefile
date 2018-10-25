include ../../../global.mk
include ../../../config-user.mk

SDBPATH=$(LTOP)/../shlr/sdb/
SDB=$(SDBPATH)/sdb

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/format

DLLS=ws2_32 oleaut32 wsock32 msi csmfpapi msvbvm60 kernel32
DLLS+=aclui activeds atl borlndmm browseui comctl32 dsound
DLLS+=mfc42 mfc42u mstlsapi msvbvm50 odbc32 olecli32 oledlg
DLLS+=olepro32 olesvr32 shdocvw shell32 shlwapi uxtheme
DLLS+=vb40032 vssapi winmm cabinet gsprop32 spr32d70 mfc90u
DLLS+=wldap32 iertutil urlmon wsnmp32 mfc30 mfc40 mfc71 mfc71u
DLLS+=mfc120
DLL_SDB=$(addsuffix .sdb,$(addprefix dll/,$(DLLS)))
#-include $(OBJS:.o=.d)

all: $(DLL_SDB)

clean:
	rm -f dll/*.sdb

.PHONY: all clean install install-symlink symstall

FORMATS=elf32 elf64 elf_enums pe32 trx mz zip

install: ${F_SDB}
	@echo "[i] Installing bin format files"
	rm -rf "$P"
	mkdir -p "$P"
	-cp -f $(FORMATS) "$P" || true
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
