include ../global.mk
include config.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}/${PREFIX}
LFX=${DESTDIR}/${LIBDIR}
IFX=${DESTDIR}/${INCLUDEDIR}
PWD=$(shell pwd)

LIBS0=util hash socket
LIBS1=reg cons db magic lib diff bp search config
LIBS2=syscall cmd lang io crypto flags bin
LIBS3=fs anal
LIBS4=parse sign
LIBS5=asm debug
LIBS6=print egg
LIBS7=core

LIBS=$(LIBS0) $(LIBS1) $(LIBS2) $(LIBS3) $(LIBS4) $(LIBS5) $(LIBS6) $(LIBS7)
.PHONY: $(LIBS)

all:
	${MAKE} $(LIBS0)
	${MAKE} $(LIBS1)
	${MAKE} $(LIBS2)
	${MAKE} $(LIBS3)
	${MAKE} $(LIBS4)
	${MAKE} $(LIBS5)
	${MAKE} $(LIBS6)
	${MAKE} $(LIBS7)

$(LIBS):
	@echo "DIR $@"
	cd $@ ; ${MAKE}

pkgcfg:
	@for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} pkgcfg ); done
	cd asm && ${MAKE} pkgcfg NAME=libr DEPS="r_`echo ${LIBS}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBS and so :)

install-pkgconfig:
	${INSTALL_DIR} ${LFX}/pkgconfig
	for a in ../pkgcfg/*.pc ; do ${INSTALL_DATA} $$a ${LFX}/pkgconfig ; done

install-includes:
	${INSTALL_DIR} ${IFX}/libr
	(cd include && for a in *.h ; do ${INSTALL_DATA} $$a ${IFX}/libr ; done)
	${INSTALL_DIR} ${IFX}/libr/sflib
	(cd include/sflib && for a in * ; do \
		${INSTALL_DIR} ${IFX}/libr/sflib/$$a ; \
		for b in $$a/*.h ; do \
			${INSTALL_DATA} $$b ${IFX}/libr/sflib/$$b ; \
		done ; \
	done)
	${INSTALL_DIR} ${IFX}/libr/sdb
	(cd include/sdb && for a in * ; do \
		${INSTALL_DATA} $$a ${IFX}/libr/sdb/$$a ; \
	done)

symstall install-symlink:
	mkdir -p ${PFX}/bin ${IFX} ${LFX}/pkgconfig ${LFX}/radare2/${VERSION}
	rm -rf ${IFX}/libr && ln -fs ${PWD}/include ${IFX}/libr
	cd ../pkgcfg && for a in *.pc ; do \
		if [ -e ${PWD}/../pkgcfg/$${a} ] ; then \
			ln -fs ${PWD}/../pkgcfg/$${a} ${LFX}/pkgconfig/$${a} ; \
		fi ; \
	done
	for a in ${LIBS} ; do \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_SO} ${LFX}/libr_$${a}.${EXT_SO} ; \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_SO} ${LFX}/libr_$${a}.${EXT_SO}.${LIBVERSION} ; \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_AR} ${LFX}/libr_$${a}.${EXT_AR} ; \
		for b in $${a}/p/*.${EXT_SO} ; do \
			if [ -e ${PWD}/$${b} ] ; then \
				ln -fs ${PWD}/$${b} ${LFX}/radare2/${VERSION}/ ; \
			fi ; \
		done ; \
	done

install: install-includes install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} ${LFX}
	@for a in `find * -type f | grep -e '\.${EXT_SO}$$' | grep -v lib/t | grep lib | grep -v /p/` ; do \
	  b=`echo $$a|cut -d / -f 2`; \
	  echo " ${LFX}/$$b.${LIBVERSION}"; \
	  ${INSTALL_LIB} $$a ${LFX}/$$b.${LIBVERSION} ; \
	  ( cd ${LFX} ; ln -fs $$b.${LIBVERSION} $$b ) ; \
	done
	# object archives
	@for a in `find * -type f | grep -e '\.a$$' | grep -v fs/p` ; do \
	  echo " ${LFX}/$$a"; ${INSTALL_DATA} $$a ${LFX} ; done
	# plugins
	@${INSTALL_DIR} ${LFX}/radare2/${VERSION}
	@for a in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${LFX}/radare2/${VERSION}/$$a"; \
	${INSTALL_DATA} $$a ${LFX}/radare2/${VERSION} ; done
	@echo "lang/p/radare.* ${DESTDIR}/${PFX}/${LIBDIR}/radare2/${VERSION}"
	${INSTALL_DATA} lang/p/radare.* ${LFX}/radare2/${VERSION}

deinstall uninstall:
	# libraries
	-@for a in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo ${LFX}/$$a ; rm -f ${LFX}/$$a ; done
	# object archives
	-@for a in `find * | grep -e '\.a$$'` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo ${LFX}/$$a ; rm -f ${LFX}/$$a ; done
	# includes
	-if [ -h ${IFX}/libr ]; then \
		rm -f ${IFX}/libr ; \
	else \
		(cd include && for a in * ; do rm -f ${IFX}/libr/$$a ; done) ; \
	fi
	# programs
	-@for a in `find */t -perm -u+x -type f | grep 2`; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PFX}/bin/$$a ; rm -f ${PFX}/bin/$$a ; done
	# plugins
	-@for a in `find */p -perm -u+x -type f`; do \
	a="${LFX}/radare2/${VERSION}/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${LFX}/radare2/${VERSION}
	rm -f ${LFX}/pkgconfig/libr.pc
	rm -f ${LFX}/pkgconfig/r_*.pc
	# test programs
	rm -rf ${PFX}/bin/libr-test
	# TODO: use for a in LIBS (like in binr/Makefile)
	rm -rf ${IFX}/libr
	rm -rf ${LFX}/libr_*.so.${LIBVERSION}
	rm -rf ${LFX}/libr_*.so.0
	rm -rf ${LFX}/libr_*.so
	rm -rf ${LFX}/libr_*.a
	rm -rf ${LFX}/libr2.so*
	rm -rf ${LFX}/libr2.a
	rm -rf ${LFX}/libr.so*
	rm -rf ${LFX}/libr.a
	rm -rf ${DESTDIR}${DATADIR}/share/doc/radare2
	@echo libr aka radare2 has been uninstalled from PREFIX=${PFX}

clean:
	for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} clean ); done

mrproper:
	for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} mrproper ); done

.PHONY: sloc mrproper clean pkgcfg install deinstall uninstall libr
.PHONY: install-includes install-pkgconfig install-symlink all
