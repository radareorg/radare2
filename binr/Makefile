include ../global.mk
BTOP=$(shell pwd)

.PHONY: all clean install install-symlink deinstall uninstall mrproper

PFX=${DESTDIR}/${PREFIX}
BFX=${DESTDIR}/${BINDIR}
LFX=${DESTDIR}/${LIBDIR}

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2 rarun2 ragg2

all:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all) || exit 1; done

install:
	mkdir -p ${BFX}
	for a in ${BINS} ; do ${INSTALL_PROGRAM} $$a/$$a ${BFX}/$$a ; done
	${INSTALL_SCRIPT} ragg2/ragg2-cc ${BFX}/ragg2-cc
	-cd ${BFX} && rm -f r2 ; ln -fs radare2 r2

symstall install-symlink:
	mkdir -p ${BFX}
	for a in ${BINS} ; do ln -fs ${BTOP}/$$a/$$a ${BFX}/$$a ; done
	ln -fs ${BTOP}/ragg2/ragg2-cc ${BFX}/ragg2-cc
	-ln -fs ${PFX}/bin/radare2 ${BFX}/r2

deinstall uninstall:
	for a in ${BINS} ; do rm -f ${BFX}/$$a ; done
	-rm -f ${BFX}/r2

clean:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} clean); done

mrproper:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} mrproper); done
