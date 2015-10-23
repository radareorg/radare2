include ../global.mk
include config.mk
include ../config-user.mk
include ../mk/platform.mk
include ../mk/${COMPILER}.mk

DESTDIR:=$(DESTDIR)
PREFIX?=${PWD}/../prefix



PWD=$(shell pwd)

LIBS0=util hash
LIBS1=reg cons db magic bp search config socket
LIBS2=syscall lang io crypto flags
LIBS3=fs anal bin
LIBS4=parse
LIBS5=asm debug
LIBS6=egg
#LIBS6+=print
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
ifeq (${WITHNONPIC},1)
	${MAKE} libr.a
endif

# looks hacky :D
#AR=arm-linux-androideabi-ar
libr.a:
	rm -rf .libr
	mkdir .libr
	for a in */libr_*.a ; do \
		mkdir -p .libr/$$a ; \
		cp -f $$a .libr/$$a ; \
		(cd .libr/$$a ; ${AR} x *.a ; rm -f *.a ) ; \
		done
	${AR} qv libr.a `find .libr/ | grep '\\.o$$'`
	rm -rf .libr

gnu_libr.a: $(shell ls */libr_*.a 2>/dev/null)
	rm -f libr.a
	echo CREATE libr.a > libr.m
	for a in */libr_*.a ; do echo ADDLIB $$a >> libr.m ; done
	echo SAVE >> libr.m
	# ar -M is a gnu-ism .. try to find a proper portable way to do that
	${CC_AR} -M < libr.m
	rm -f libr.m

$(LIBS):
	@echo "DIR $@"
	@${MAKE} -C $@

pkgcfg:
	@for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} pkgcfg ); done
	cd asm && ${MAKE} pkgcfg NAME=libr DEPS="r_`echo ${LIBS}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBS and so :)

install-pkgconfig:
	${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for a in ../pkgcfg/*.pc ; do \
		rm -f "${DESTDIR}${LIBDIR}/pkgconfig/$$a" ; \
		${INSTALL_DATA} $$a "${DESTDIR}${LIBDIR}/pkgconfig" ; done

install-includes:
	@-rm -f ${DESTDIR}${INCLUDEDIR}/libr/sflib
	@-rm -f ${DESTDIR}${INCLUDEDIR}/libr
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr"
	(cd include && for a in *.h ; do ${INSTALL_DATA} $$a "${DESTDIR}${INCLUDEDIR}/libr" ; done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib"
	(cd include/sflib && for a in * ; do \
		${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$a" ; \
		for b in $$a/*.h ; do \
			${INSTALL_DATA} $$b "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$b" ; \
		done ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sdb"
	(cd include/sdb && for a in * ; do \
		${INSTALL_DATA} $$a "${DESTDIR}${INCLUDEDIR}/libr/sdb/$$a" ; \
	done)

symstall install-symlink:
	mkdir -p "${DESTDIR}${BINDIR}" \
		"${DESTDIR}${INCLUDEDIR}" \
		"${DESTDIR}${LIBDIR}/pkgconfig" \
		"${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr" && ln -fs "${PWD}/include" "${DESTDIR}${INCLUDEDIR}/libr"
	cd ../pkgcfg && for a in *.pc ; do \
		if [ -e "${PWD}/../pkgcfg/$${a}" ] ; then \
			ln -fs "${PWD}/../pkgcfg/$${a}" \
				"${DESTDIR}${LIBDIR}/pkgconfig/$${a}" ; \
		fi ; \
	done
	@$(foreach lib,${LIBS}, \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/libr_$(lib).${EXT_SO}" ; \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/$(call libname-version,libr_$(lib).${EXT_SO},${LIBVERSION})" ; \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_AR}" "${DESTDIR}${LIBDIR}/libr_$(lib).${EXT_AR}" ; \
	  $(foreach module,$(wildcard $(lib)/p/*.${EXT_SO}), \
	    ln -fs "${PWD}/$(module)" "${DESTDIR}${LIBDIR}/radare2/${VERSION}/" ; \
	  ) \
	)
	cd "${DESTDIR}${LIBDIR}/radare2" ; rm -f last ; ln -fs "${VERSION}" last

install: install-includes install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}"
	@$(foreach lib,$(shell find * -type f | grep -e '\.${EXT_SO}$$' | grep -Ev '(lib|parse)/t/' | grep lib | grep -v /bin/ | grep -v /p/), \
	  echo " ${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  rm -f "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ${INSTALL_LIB} "$(lib)" "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ( cd "${DESTDIR}${LIBDIR}" ; ln -fs "$(call libpath-to-name-version,$(lib),${LIBVERSION})" "$(call libpath-to-name,$(lib))" ) ; \
	)
	# object archives
	@for a in `find * -type f | grep -e '\.a$$' | grep -v fs/p` ; do \
	  echo " ${DESTDIR}${LIBDIR}/$$a"; ${INSTALL_DATA} $$a ${DESTDIR}${LIBDIR} ; done
	# plugins
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	@for a in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${DESTDIR}${LIBDIR}/radare2/${VERSION}/$$a"; \
	${INSTALL_LIB} "$$a" "${DESTDIR}${LIBDIR}/radare2/${VERSION}" ; done
	cd "${DESTDIR}${LIBDIR}/radare2" ; ln -fs "${VERSION}" last

#@echo "lang/p/radare.* ${DESTDIR}${DESTDIR}${PREFIX}/${LIBDIR}/radare2/${VERSION}"
#${INSTALL_DATA} lang/p/radare.* ${DESTDIR}${LIBDIR}/radare2/${VERSION}

deinstall uninstall:
	# libraries
	-@for a in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$a" ; rm -f "${DESTDIR}${LIBDIR}/$$a" ; done
	# object archives
	-@for a in `find * | grep -e '\.a$$'` ; do \
	a=`echo $$a | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$a" ; rm -f "${DESTDIR}${LIBDIR}/$$a" ; done
	# includes
	-if [ -h "${DESTDIR}${INCLUDEDIR}/libr" ]; then \
		rm -f "${DESTDIR}${INCLUDEDIR}/libr" ; \
	else \
		(cd include && for a in * ; do rm -f "${DESTDIR}${INCLUDEDIR}/libr/$$a" ; done) ; \
	fi
	# programs
	-@for a in `find */t -perm -u+x -type f | grep 2`; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${BINDIR}/$$a" ; rm -f "${DESTDIR}${BINDIR}/$$a" ; done
	# plugins
	-@for a in `find */p -perm -u+x -type f`; do \
	a="${DESTDIR}${LIBDIR}/radare2/${VERSION}/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/libr.pc"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/r_"*.pc
	# test programs
	rm -rf "${DESTDIR}${BINDIR}/libr-test"
	# TODO: use for a in LIBS (like in binr/Makefile)
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.${LIBVERSION}"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.0"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.a"
	rm -rf "${DESTDIR}${LIBDIR}/libr2.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr2.a"
	rm -rf "${DESTDIR}${LIBDIR}/libr.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr.a"
	rm -rf "${DESTDIR}${DATADIR}/doc/radare2"
	@echo libr aka radare2 has been uninstalled from PREFIX=${DESTDIR}${PREFIX}

clean:
	for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} clean ); done

mrproper:
	for lib in ${LIBS}; do ( cd $${lib} && ${MAKE} mrproper ); done

.PHONY: sloc mrproper clean pkgcfg install deinstall uninstall libr
.PHONY: install-includes install-pkgconfig install-symlink all
