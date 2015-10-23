include ../global.mk
include ../libr/config.mk

DESTDIR:=$(DESTDIR)
BTOP=$(shell pwd)

.PHONY: all clean install install-symlink deinstall uninstall mrproper preload





BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2 rarun2 ragg2 r2agent
# this command needs more love to bring it back
#BINS+=ranal2

LIBR2=$(call libname-version,libr2.$(EXT_SO),${LIBVERSION})

all: preload
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all) || exit 1; done

preload:
	$(MAKE) -C preload

install:
	mkdir -p "${DESTDIR}${BINDIR}"
	for a in ${BINS} ; do \
		rm -f "${DESTDIR}${BINDIR}/$$a" ; \
		${INSTALL_PROGRAM} "$$a/$$a" "${DESTDIR}${BINDIR}/$$a" ; \
	done
	${INSTALL_SCRIPT} "$(BTOP)/r2pm/r2pm" "${DESTDIR}${BINDIR}/r2pm"
	rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	rm -rf "${DESTDIR}${PREFIX}/radare2/${VERSION}/r2pm"
	mkdir -p "${DESTDIR}${PREFIX}/radare2/${VERSION}/r2pm"
	cp -rf r2pm/d/* "${DESTDIR}${PREFIX}/radare2/${VERSION}/r2pm"
	${INSTALL_SCRIPT} ragg2/ragg2-cc "${DESTDIR}${BINDIR}/ragg2-cc"
	-cd "${DESTDIR}${BINDIR}" && rm -f r2 ; ln -fs radare2 r2
	${INSTALL_LIB} "preload/libr2.$(EXT_SO)" "${DESTDIR}${LIBDIR}"
	-cd "${DESTDIR}${LIBDIR}" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

symstall install-symlink:
	mkdir -p "${DESTDIR}${BINDIR}"
	for a in ${BINS} ; do ln -fs "${BTOP}/$$a/$$a" "${DESTDIR}${BINDIR}/$$a" ; done
	ln -fs "${BTOP}/ragg2/ragg2-cc" "${DESTDIR}${BINDIR}/ragg2-cc"
	ln -fs "${BTOP}/r2pm/r2pm" "${DESTDIR}${BINDIR}/r2pm"
	rm -rf "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	ln -fs "$(BTOP)/r2pm/d" "${DESTDIR}${DATADIR}/radare2/${VERSION}/r2pm"
	-ln -fs "${DESTDIR}${BINDIR}/radare2" "${DESTDIR}${BINDIR}/r2"
	-ln -fs "${BTOP}/preload/libr2.$(EXT_SO)" "${DESTDIR}${LIBDIR}/libr2.$(EXT_SO)"
	-cd "${DESTDIR}${LIBDIR}" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

deinstall uninstall:
	for a in ${BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$a" ; done
	-rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	-rm -f "${DESTDIR}${BINDIR}/r2pm"
	-rm -f "${DESTDIR}${BINDIR}/r2"

clean:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} clean); done

mrproper:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} mrproper); done
