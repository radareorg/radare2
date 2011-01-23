include ../global.mk
include config.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}${PREFIX}
#PREFIX=${PFX}

# Libraries
LIBLIST=util vm socket cons line lib io lang flags bin hash config syscall cmd
LIBLIST+=reg asm anal print parse search diff bp sign th db crypto debug fs core

# TODO : generate single library linking against the rest
#LIBSO=libr.so
#LIBAR=libr.a

all: libs libr

libs:
	@for lib in ${LIBLIST}; do \
		cd $${lib} && ${MAKE} all || exit 1 ; cd .. ; done
	@echo Build done for: ${LIBLIST}

ifeq ($(ONELIB),1)
libr: .objs
	$(MAKE) libr2.${EXT_SO} libr2.${EXT_AR}
else
libr:
endif

ifeq ($(WITHPIC),1)
libr2.${EXT_SO}: .objs
ifeq ($(OSTYPE),darwin)
	@echo Linkage of libr2.dylib is broken on OSX because of dupped .o in .objs extraction
else
	${CC} -shared -fPIC ${LDFLAGS_SONAME}libr2.${EXT_SO}.${VERSION} ${PIC_CFLAGS} .objs/*.o -o libr2.${EXT_SO}
endif

libr2.${EXT_AR}:
	@echo NOTE: Use --without-pic in configure to create libr2.${EXT_AR}
else
libr2.${EXT_SO}:

ifeq ($(WITHNONPIC),1)
libr2.${EXT_AR}:
	ar -r libr2.${EXT_AR} .objs/*.o
else
libr2.${EXT_AR}:
	@# do nothing
endif
endif

# XXX needs autodetection of deps to remake and so..
.objs:
	cd vm ; sh ../waitfordeps.sh r_`echo ${LIBLIST}|sed -e 's, , r_,g'`
	mkdir -p .objs
	-for a in ${LIBLIST} ; do \
		(cd .objs && ar x ../$$a/libr_$$a.a) ; \
	done

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
	@for a in `find * | grep -e '\.${EXT_SO}$$' | grep -v lib/t | grep lib` ; do \
	  b=`echo $$a|cut -d / -f 2`; \
	  echo " ${PFX}/lib/$$b.${VERSION}"; \
	  ${INSTALL_LIB} $$a ${PFX}/lib/$$b.${VERSION} ; \
	  ( cd ${PFX}/lib ; ln -fs $$b.${VERSION} $$b.0 ; ln -fs $$b.0 $$b ); \
	done
	# object archives
	@for a in `find * | grep -e '\.a$$'` ; do \
	  echo " ${PFX}/lib/$$a"; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# plugins
	@${INSTALL_DIR} ${PFX}/lib/radare2/${VERSION}
	@for a in `find */p -perm -u+x -type f | grep -v exe | grep -v dll`; \
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
	rm -f libr2.so
	rm -rf .objs

mrproper:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} mrproper ); done
	rm -f libr2.so
	rm -rf .objs
	rm -f libr.pc

sloc:
	${MAKE} -C .. sloc SLOCDIR=libr

.PHONY: sloc mrproper clean all pkgcfg install deinstall uninstall libr install-symlink
