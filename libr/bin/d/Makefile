include ../../../global.mk
include ../../../config-user.mk

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/format

DLLS=ws2_32 oleaut32 wsock32 msi csmfpapi msvbvm60 kernel32
DLLS+=aclui activeds atl borlndmm browseui comctl32 dsound
DLLS+=mfc42 mfc42u mstlsapi msvbvm50 odbc32 olecli32 oledlg
DLLS+=olepro32 olesvr32 shdocvw shell32 shlwapi uxtheme
DLLS+=vb40032 vssapi winmm cabinet gsprop32 spr32d70 mfc90u
DLLS+=wldap32 iertutil urlmon wsnmp32 mfc30 mfc40 mfc71 mfc71u
DLLS+=mfc120 csmtpapi csncdapi mfc140u mfc100u
# ne
DLLS+=avicap avifile awdevl16 cards cmc comm commctrl commdlg compobj
DLLS+=cspman dciman ddeml deskcp16 dibeng dispdib display dskmaint
DLLS+=enable3 faxcodec gdi inet16 iosclass kernel keyboard lzexpand
DLLS+=maincp16 mapi mapiu mapix mciavi mcicda mcimidi mciole
DLLS+=mciwave midimap ml3xec16 mmci mmsystem modem modemui mouse
DLLS+=msacm msacmmap msdos msdosd msjstick msmixmgr mspcic
DLLS+=msprint mstcp msvideo netapi netcpl netdi netos netware
DLLS+=nw16 ole2 ole2conv ole2disp ole2nls olecli olesvr pifmgr
DLLS+=pkpd pmspl power rasapi16 rnasetup rsrc16 sb16snd sbfm
DLLS+=setup4 setupx shell sound spooler storage sysclass sysdetmg
DLLS+=sysdm sysedit system systhunk tapi tapiaddr
DLLS+=toolhelp typelib umdm16 user ver whlp16t win32s16
DLLS+=win87em winaspi winnet16 winoldap winsock winspl16 wpsapd wpsuni
DLLS+=wpsunire wsasrv
DLL_SDB=$(addsuffix .sdb,$(addprefix dll/,$(DLLS)))

all:
	$(SDB) -r $(shell pwd)
	$(SDB) -r $(shell pwd)/dll

clean:
	rm -f dll/*.sdb

.PHONY: all clean install install-symlink symstall uninstall

install: $(F_SDB)
	@echo "[i] Installing bin format files"
	rm -rf "$P"
	mkdir -p "$P"
	-cp -f *.r2 *.h "$P" || true
	-cp -f symclass.sdb "$P" || true
	mkdir -p "$P/dll"
	cp -f dll/*.sdb "$P/dll"

CWD=$(shell pwd)
symstall install-symlink:
	mkdir -p "$P"
	rm -rf "$P/dll"
	for FILE in *.r2 *.h dll symclass.sdb ; do \
		[ ! -d "$P/$$FILE" ] && ln -fs "${CWD}/$$FILE" "$P/$$FILE" ; \
	done


uninstall:
	rm -rf "$P"
