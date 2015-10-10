include ../global.mk
include ../libr/config.mk

DESTDIR:=$(call rmbdlslash,$(DESTDIR))
BTOP=$(shell pwd)

.PHONY: all clean install install-symlink deinstall uninstall mrproper preload

PFX=$(call rmdblslash,${DESTDIR}/${PREFIX})
BFX=$(call rmdblslash,${DESTDIR}/${BINDIR})
LFX=$(call rmdblslash,${DESTDIR}/${LIBDIR})

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2 rarun2 ragg2 r2agent
# this command needs more love to bring it back
#BINS+=ranal2

LIBR2=$(call libname-version,libr2.$(EXT_SO),${LIBVERSION})

all: preload
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all) || exit 1; done

preload:
	$(MAKE) -C preload

install:
	mkdir -p "${BFX}"
	for a in ${BINS} ; do \
		rm -f "${BFX}/$$a" ; \
		${INSTALL_PROGRAM} "$$a/$$a" "${BFX}/$$a" ; \
	done
	${INSTALL_SCRIPT} "$(BTOP)/r2pm/r2pm" "${BFX}/r2pm"
	rm -f "${BFX}/ragg2-cc"
	rm -rf "${PFX}/radare2/${VERSION}/r2pm"
	mkdir -p "${PFX}/radare2/${VERSION}/r2pm"
	cp -rf r2pm/d/* "${PFX}/radare2/${VERSION}/r2pm"
	${INSTALL_SCRIPT} ragg2/ragg2-cc "${BFX}/ragg2-cc"
	-cd "${BFX}" && rm -f r2 ; ln -fs radare2 r2
	${INSTALL_LIB} "preload/libr2.$(EXT_SO)" "$(LFX)"
	-cd "$(LFX)" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

symstall install-symlink:
	mkdir -p "${BFX}"
	for a in ${BINS} ; do ln -fs "${BTOP}/$$a/$$a" "${BFX}/$$a" ; done
	ln -fs "${BTOP}/ragg2/ragg2-cc" "${BFX}/ragg2-cc"
	ln -fs "${BTOP}/r2pm/r2pm" "${BFX}/r2pm"
	rm -rf "${PFX}/share/radare2/${VERSION}/r2pm"
	mkdir -p "${PFX}/share/radare2/${VERSION}/"
	ln -fs "$(BTOP)/r2pm/d" "${PFX}/share/radare2/${VERSION}/r2pm"
	-ln -fs "${PFX}/bin/radare2" "${BFX}/r2"
	-ln -fs "${BTOP}/preload/libr2.$(EXT_SO)" "${LFX}/libr2.$(EXT_SO)"
	-cd "$(LFX)" && \
		mv libr2.$(EXT_SO) $(LIBR2) && \
		ln -fs $(LIBR2) libr2.$(EXT_SO)

deinstall uninstall:
	for a in ${BINS} ; do rm -f "${BFX}/$$a" ; done
	-rm -f "${BFX}/ragg2-cc"
	-rm -f "${BFX}/r2pm"
	-rm -f "${BFX}/r2"

clean:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} clean); done

mrproper:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} mrproper); done
