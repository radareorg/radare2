include ../config-user.mk

.PHONY: all clean

BINS=rax2 rasm2 rabin2 rahash2 radiff2 radare2

all:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} all); done

install:
	for a in ${BINS} ; do ${INSTALL_PROGRAM} $$a/$$a ${DESTDIR}/${PREFIX}/bin ; done
	# shortcut
	-cd ${PFX}/bin && rm -f r2 ; ln -fs radare2 r2

clean:
	@for a in ${BINS} ; do (cd $$a && ${MAKE} clean); done
