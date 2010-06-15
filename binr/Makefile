include ../config-user.mk

.PHONY: all clean install install-symlink deinstall uninstall mrproper

PFX=${DESTDIR}${PREFIX}

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2

all:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all); done

install:
	mkdir -p ${PFX}/bin
	for a in ${BINS} ; do ${INSTALL_PROGRAM} $$a/$$a ${PFX}/bin ; done
	# shortcut
	-cd ${PFX}/bin && rm -f r2 ; ln -fs radare2 r2

install-symlink:
	mkdir -p ${PFX}/bin
	for a in ${BINS} ; do ln -fs ${PWD}/$$a/$$a ${PFX}/bin/$$a ; done
	-ln -fs ${PFX}/bin/radare2 ${PFX}/bin/r2

deinstall uninstall:
	for a in ${BINS} ; do rm -f ${PFX}/bin/$$a ; done
	-rm -f ${PFX}/bin/r2

mrproper:clean

clean:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} clean); done
