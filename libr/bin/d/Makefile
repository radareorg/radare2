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
DLLS+=mfc120 csmtpapi csncdapi mfc140u mfc100u
# NE
DLLS+=AVICAP AVIFILE AWDEVL16 CARDS CMC COMM COMMCTRL COMMDLG COMPOBJ
DLLS+=CSPMAN DCIMAN DDEML DESKCP16 DIBENG DISPDIB DISPLAY DSKMAINT
DLLS+=ENABLE3 FAXCODEC GDI INET16 IOSCLASS KERNEL KEYBOARD LZEXPAND
DLLS+=MAINCP16 MAPI MAPIU MAPIX MCIAVI MCICDA MCIMIDI MCIOLE
DLLS+=MCIWAVE MIDIMAP ML3XEC16 MMCI MMSYSTEM MODEM MODEMUI MOUSE
DLLS+=MSACM MSACMMAP MSDOS MSDOSD MSGSRV32 MSJSTICK MSMIXMGR MSPCIC
DLLS+=MSPRINT MSTCP MSVIDEO NETAPI NETCPL NETDI NETOS NETWARE
DLLS+=NW16 OLE2 OLE2CONV OLE2DISP OLE2NLS OLECLI OLESVR PIFMGR
DLLS+=PKPD PMSPL POWER RASAPI16 RNASETUP RSRC16 SB16SND SBFM
DLLS+=SETUP4 SETUPX SHELL SOUND SPOOLER STORAGE SYSCLASS SYSDETMG
DLLS+=SYSDM SYSEDIT SYSTEM SYSTHUNK TAPI TAPIADDR TAPIEXE
DLLS+=TAPIINI TOOLHELP TYPELIB UMDM16 USER VER WHLP16T WIN32S16
DLLS+=WIN87EM WINASPI WINNET16 WINOLDAP WINSOCK WINSPL16 WPSAPD WPSUNI
DLLS+=WPSUNIRE WSASRV
DLL_SDB=$(addsuffix .sdb,$(addprefix dll/,$(DLLS)))

all: $(DLL_SDB)

clean:
	rm -f dll/*.sdb

.PHONY: all clean install install-symlink symstall

FORMATS=dex macho elf32 elf64 elf_enums pe32 trx mz zip

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
