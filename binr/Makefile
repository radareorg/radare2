include ../config-user.mk
PWD=$(shell pwd)

.PHONY: all clean install install-symlink deinstall uninstall mrproper

PFX=${DESTDIR}${PREFIX}

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2 rafind2 rarc2 ranal2 rasc2 rsc2

all:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all) || exit 1; done

install:
	mkdir -p ${PFX}/bin
	for a in ${BINS} ; do ${INSTALL_PROGRAM} $$a/$$a ${PFX}/bin ; done
	# rarc2
	cp -f rarc2/rarc2 ${PFX}/bin
	cp -f rarc2/rarc2-tool ${PFX}/bin
	# shortcut
	-cd ${PFX}/bin && rm -f r2 ; ln -fs radare2 r2
	mkdir -p ${PFX}/lib/radare/bin
	cp -f rsc2/scripts/* ${PFX}/lib/radare/bin
	chmod +x ${PFX}/lib/radare/bin/*

symstall install-symlink:
	mkdir -p ${PFX}/bin
	mkdir -p ${PFX}/lib/radare/bin
	chmod +x rsc2/scripts/*
	cd rsc2/scripts ; for a in * ; do ln -fs ${PWD}/rsc2/scripts/$$a ${PFX}/lib/radare/bin/$$a ; done
	for a in ${BINS} ; do ln -fs ${PWD}/$$a/$$a ${PFX}/bin/$$a ; done
	ln -fs ${PWD}/rarc2/rarc2-tool ${PFX}/bin/rarc2-tool
	-ln -fs ${PFX}/bin/radare2 ${PFX}/bin/r2

deinstall uninstall:
	for a in ${BINS} ; do rm -f ${PFX}/bin/$$a ; done
	rm -f ${PFX}/bin/rarc2-tool
	-rm -f ${PFX}/bin/r2

clean:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} clean); done

mrproper:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} mrproper); done
