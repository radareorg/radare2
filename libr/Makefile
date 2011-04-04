include ../global.mk
include config.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}${PREFIX}
PWD=`pwd`
#PREFIX=${PFX}

# Libraries
LIBLIST=util socket cons line lib io lang flags bin hash config syscall cmd
LIBLIST+=reg asm diff anal print parse search bp sign db crypto debug fs core
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
	@${INSTALL_DIR} ${PFX}/lib/pkgconfig
	for a in ../pkgcfg/*.pc ; do ${INSTALL_DATA} $$a ${PFX}/lib/pkgconfig ; done

install-includes:
	@${INSTALL_DIR} ${PFX}/include/libr
	(cd include && ${INSTALL_DATA} * ${PFX}/include/libr)

install-symlink:
	mkdir -p ${PFX}/bin
	mkdir -p ${PFX}/include
	mkdir -p ${PFX}/lib/pkgconfig
	mkdir -p ${PFX}/lib/radare2/${VERSION}
	rm -f ${PFX}/include/libr && ln -fs ${PWD}/include ${PFX}/include/libr
	cd ../pkgcfg && for a in *.pc ; do \
		if [ -e ${PWD}/../pkgcfg/$${a} ] ; then \
			ln -fs ${PWD}/../pkgcfg/$${a} ${PFX}/lib/pkgconfig/$${a} ; \
		fi ; \
	done
	for a in ${LIBLIST} ; do \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_SO} ${PFX}/lib/libr_$${a}.${EXT_SO} ; \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_SO} ${PFX}/lib/libr_$${a}.${EXT_SO}.${VERSION} ; \
		ln -fs ${PWD}/$${a}/libr_$${a}.${EXT_AR} ${PFX}/lib/libr_$${a}.${EXT_AR} ; \
		for b in $${a}/p/*.${EXT_SO} ; do \
			if [ -e ${PWD}/$${b} ] ; then \
				ln -fs ${PWD}/$${b} ${PFX}/lib/radare2/${VERSION}/ ; \
			fi ; \
		done ; \
	done

install: install-includes install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} ${PFX}/lib
	@for a in `find * -type f | grep -e '\.${EXT_SO}$$' | grep -v lib/t | grep lib | grep -v /p/` ; do \
	  b=`echo $$a|cut -d / -f 2`; \
	  echo " ${PFX}/lib/$$b.${VERSION}"; \
	  ${INSTALL_LIB} $$a ${PFX}/lib/$$b.${VERSION} ; \
	  ( cd ${PFX}/lib ; ln -fs $$b.${VERSION} $$b.0 ; ln -fs $$b.0 $$b ); \
	done
	# object archives
	@for a in `find * -type f | grep -e '\.a$$' | grep -v fs/p` ; do \
	  echo " ${PFX}/lib/$$a"; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# plugins
	@${INSTALL_DIR} ${PFX}/lib/radare2/${VERSION}
	@for a in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${PFX}/lib/radare2/${VERSION}/$$a"; \
	${INSTALL_DATA} $$a ${PFX}/lib/radare2/${VERSION} ; done
	@echo "lang/p/radare.* ${PFX}/lib/radare2/${VERSION}"
	${INSTALL_DATA} lang/p/radare.* ${PFX}/lib/radare2/${VERSION}

deinstall uninstall:
	# libraries
	-@for a in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo ${PFX}/lib/$$a ; rm -f ${PFX}/lib/$$a ; done
	# object archives
	-@for a in `find * | grep -e '\.a$$'` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo ${PFX}/lib/$$a ; rm -f ${PFX}/lib/$$a ; done
	# includes
	-(cd include && for a in * ; do rm -f ${PFX}/libr/$$a ; done)
	# programs
	-@for a in `find */t -perm -u+x -type f | grep 2`; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PFX}/bin/$$a ; rm -f ${PFX}/bin/$$a ; done
	# plugins
	-@for a in `find */p -perm -u+x -type f`; do \
	a="${PFX}/lib/radare2/${VERSION}/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PFX}/lib/radare2/${VERSION}
	rm -f ${PFX}/lib/pkgconfig/libr.pc
	rm -f ${PFX}/lib/pkgconfig/r_*.pc
	# test programs
	rm -rf ${PFX}/bin/libr-test
	# TODO: use for a in LIBLIST (like in binr/Makefile)
	rm -rf ${PFX}/include/libr
	rm -rf ${PFX}/lib/libr_*.so.${VERSION}
	rm -rf ${PFX}/lib/libr_*.so.0
	rm -rf ${PFX}/lib/libr_*.so
	rm -rf ${PFX}/lib/libr_*.a
	rm -rf ${PFX}/lib/libr2.so*
	rm -rf ${PFX}/lib/libr2.a
	rm -rf ${PFX}/lib/libr.so*
	rm -rf ${PFX}/lib/libr.a
	rm -rf ${PFX}/share/doc/radare2
	@echo libr aka radare2 has been uninstalled from PREFIX=${PFX}

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done

mrproper:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} mrproper ); done

sloc:
	${MAKE} -C .. sloc SLOCDIR=libr

.PHONY: sloc mrproper clean all pkgcfg install deinstall uninstall libr install-symlink
