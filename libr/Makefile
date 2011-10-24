include ../global.mk
include config.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}/${PREFIX}
LFX=${DESTDIR}/${LIBDIR}
IFX=${DESTDIR}/${INCLUDEDIR}
PWD=`pwd`

# Libraries
LIBLIST=util magic socket db cons line lib io lang flags bin hash config syscall
LIBLIST+=cmd reg diff anal parse asm print search egg bp sign debug fs core th
#DEPRECATED APIS : LIBLIST+=th crypto
# sysproxy ... common wat du?

all: libs

libs:
	@for lib in ${LIBLIST}; do \
		cd $${lib} && ${MAKE} all || exit 1 ; cd .. ; done
	@echo Build done for: ${LIBLIST}

pkgcfg:
	@for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} pkgcfg ); done
	# XXX
	cd asm && ${MAKE} pkgcfg NAME=libr DEPS="r_`echo ${LIBLIST}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBLIST and so :)

install-pkgconfig:
	${INSTALL_DIR} ${LFX}/pkgconfig
	for a in ../pkgcfg/*.pc ; do ${INSTALL_DATA} $$a ${LFX}/pkgconfig ; done

install-includes:
	${INSTALL_DIR} ${IFX}/libr
	(cd include && for a in *.h ; do ${INSTALL_DATA} $$a ${IFX}/libr ; done)

install-symlink:
	mkdir -p ${PFX}/bin
	mkdir -p ${IFX}
	mkdir -p ${LFX}/pkgconfig
	mkdir -p ${LFX}/radare2/${VERSION}
	rm -rf ${IFX}/libr && ln -fs ${PWD}/include ${IFX}/libr
	cd ../pkgcfg && for a in *.pc ; do \
		if [ -e ${PWD}/../pkgcfg/$${a} ] ; then \
			ln -fs ${PWD}/../pkgcfg/$${a} ${LFX}/pkgconfig/$${a} ; \
		fi ; \
	done
	for a in ${LIBLIST} ; do \
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
	#Linux only? ( cd ${LFX} ; ln -fs $$b.${LIBVERSION} $$b.0 ; ln -fs $$b.0 $$b )
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
	# TODO: use for a in LIBLIST (like in binr/Makefile)
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
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done

mrproper:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} mrproper ); done

sloc:
	${MAKE} -C .. sloc SLOCDIR=libr

.PHONY: sloc mrproper clean all pkgcfg install deinstall uninstall libr install-symlink
