include ../global.mk
include ../libr/config.mk

DESTDIR:=$(DESTDIR)
BTOP=$(shell pwd)

.PHONY: all clean install install-symlink deinstall uninstall mrproper preload

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2 rarun2 ragg2 r2agent

LIBR2=$(call libname-version,libr2.$(EXT_SO),${LIBVERSION})

all: preload
	@for BINARY in ${BINS} ; do (cd $$BINARY && ${MAKE} all) || exit 1; done
ifeq ($(COMPILER),ios-sdk)
	$(MAKE) ios-sign
endif

preload:
	$(MAKE) -C preload

install:
	mkdir -p "${DESTDIR}${BINDIR}"
	for BINARY in ${BINS} ; do \
		rm -f "${DESTDIR}${BINDIR}/$$BINARY" ; \
		${INSTALL_PROGRAM} "$$BINARY/$$BINARY" "${DESTDIR}${BINDIR}/$$BINARY" ; \
	done
	${INSTALL_SCRIPT} "$(BTOP)/r2pm/r2pm" "${DESTDIR}${BINDIR}/r2pm"
	rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	#mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	#cp -rf r2pm/d/* "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	${INSTALL_SCRIPT} ragg2/ragg2-cc "${DESTDIR}${BINDIR}/ragg2-cc"
	-cd "${DESTDIR}${BINDIR}" && rm -f r2 ; ln -fs radare2 r2
	${INSTALL_LIB} "preload/libr2.$(EXT_SO)" "${DESTDIR}${LIBDIR}"
	-cd "${DESTDIR}${LIBDIR}" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

ios_sign ios-sign ios-sdk-sign:
	for a in $(BINS) ; do xcrun --sdk iphoneos codesign -s- --entitlements radare2/radare2.xml $$a ; done

symstall install-symlink:
	mkdir -p "${DESTDIR}${BINDIR}"
	for BINARY in ${BINS} ; do ln -fs "${BTOP}/$$BINARY/$$BINARY" "${DESTDIR}${BINDIR}/$$BINARY" ; done
	ln -fs "${BTOP}/ragg2/ragg2-cc" "${DESTDIR}${BINDIR}/ragg2-cc"
	ln -fs "${BTOP}/r2pm/r2pm" "${DESTDIR}${BINDIR}/r2pm"
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	#ln -fs "$(BTOP)/r2pm/d" "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	-ln -fs "${DESTDIR}${BINDIR}/radare2" "${DESTDIR}${BINDIR}/r2"
	-ln -fs "${BTOP}/preload/libr2.$(EXT_SO)" "${DESTDIR}${LIBDIR}/libr2.$(EXT_SO)"
	-cd "${DESTDIR}${LIBDIR}" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

deinstall uninstall:
	for BINARY in ${BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$BINARY" ; done
	-rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	-rm -f "${DESTDIR}${BINDIR}/r2pm"
	-rm -f "${DESTDIR}${BINDIR}/r2"

clean:
	@for DIR in preload ${BINS} ; do (cd $$DIR && ${MAKE} clean); done

mrproper:
	@for DIR in preload ${BINS} ; do (cd $$DIR && ${MAKE} mrproper); done

