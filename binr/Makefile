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

all: preload
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all) || exit 1; done

preload:
	$(MAKE) -C preload

install:
	mkdir -p "${BFX}"
	for a in ${BINS} ; do ${INSTALL_PROGRAM} "$$a/$$a" "${BFX}/$$a" ; done
	${INSTALL_SCRIPT} ragg2/ragg2-cc "${BFX}/ragg2-cc"
	-cd "${BFX}" && rm -f r2 ; ln -fs radare2 r2
	${INSTALL_LIB} "preload/libr2.$(EXT_SO)" "$(LFX)"
	-cd "$(LFX)" && \
		mv libr2.$(EXT_SO) libr2.$(EXT_SO).$(VERSION) && \
		ln -fs libr2.$(EXT_SO).$(VERSION) libr2.$(EXT_SO)

symstall install-symlink:
	mkdir -p "${BFX}"
	for a in ${BINS} ; do ln -fs "${BTOP}/$$a/$$a" "${BFX}/$$a" ; done
	ln -fs "${BTOP}/ragg2/ragg2-cc" "${BFX}/ragg2-cc"
	-ln -fs "${PFX}/bin/radare2" "${BFX}/r2"
	-ln -fs "${BTOP}/preload/libr2.$(EXT_SO)" "${LFX}/libr2.$(EXT_SO)"
	-cd "$(LFX)" && \
		mv libr2.$(EXT_SO) libr2.$(EXT_SO).$(VERSION) && \
		ln -fs libr2.$(EXT_SO).$(VERSION) libr2.$(EXT_SO)

deinstall uninstall:
	for a in ${BINS} ; do rm -f "${BFX}/$$a" ; done
	-rm -f "${BFX}/r2"

clean:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} clean); done

mrproper:
	@for a in preload ${BINS} ; do (cd $$a && ${MAKE} mrproper); done
