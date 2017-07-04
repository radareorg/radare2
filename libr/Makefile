include ../global.mk
include config.mk
include ../config-user.mk
include ../mk/platform.mk
include ../mk/${COMPILER}.mk

DESTDIR:=$(DESTDIR)
PREFIX?=${PWD}/../prefix

PWD=$(shell pwd)

LIBS0=util hash
LIBS1=socket reg cons magic bp search config
LIBS2=syscall lang io crypto flag
LIBS3=fs anal bin parse
LIBS4=asm
LIBS5=egg
LIBS6=debug
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
	${MAKE} libr.${EXT_AR}
endif

# looks hacky :D
#AR=arm-linux-androideabi-ar

S=$
B=`
libr.${EXT_AR}:
	rm -rf .libr
	mkdir .libr
	for FILE in */libr_*.${EXT_AR} ../shlr/*/*.${EXT_AR} ; do \
		F=${B}basename $$FILE${B} ; \
		Q=${B}dirname $$FILE${B} ; \
		D=${B}basename $$Q${B} ; \
		mkdir -p .libr/$$D ; \
		cp -f $$FILE .libr/$$D/$$F ; \
		ls -l .libr/$$D/$$F ; \
		(cd .libr/$$D && ${AR} x $$F || true ) ; \
	done
	echo lets ar
	cd .libr ; ${AR} qv libr.${EXT_AR} `find * -iname *.${EXT_AR} 2> /dev/null`
	echo lets m
	mv .libr/libr.${EXT_AR} libr.${EXT_AR}
	echo ranlibin
	${RANLIB} libr.${EXT_AR}

libr.${EXT_SO}:
	rm -rf .libr/tcc
	#xcrun --sdk iphoneos clang -shared -dynamic -arch arm64 -o libr.${EXT_SO} .libr/*/*.o ../shlr/gdb/lib/libgdbr.a
	$(CC) -shared -dynamic -arch arm64 -o libr.${EXT_SO} .libr/*/*.o ../shlr/gdb/lib/libgdbr.a
	#rm -rf .libr

__AR=xcrun --sdk iphoneos ar
__RANLIB=xcrun --sdk iphoneos ranlib
a:
	rm -rf .libr
	mkdir .libr
	for FILE in */libr_*.${EXT_AR} ; do \
		mkdir -p .libr/$$FILE ; \
		cp -f $$FILE .libr/$$FILE ; \
		(cd .libr/$$FILE ; ${__AR} x *.${EXT_AR} ; rm -f *.${EXT_AR} ) ; \
		done
	cd .libr ; ${__AR} qv libr.${EXT_AR} `find * -iname *.o`
	mv .libr/libr.${EXT_AR} libr.${EXT_AR}
	${__RANLIB} libr.${EXT_AR}
	lipo -info libr.${EXT_AR}
	rm -rf .libr

gnu_libr.${EXT_AR}: $(shell ls */libr_*.${EXT_AR} 2>/dev/null)
	rm -f libr.
	echo CREATE libr.${EXT_AR} > libr.m
	for FILE in */libr_*.${EXT_AR} ; do echo ADDLIB $$FILE >> libr.m ; done
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
	for FILE in ../pkgcfg/*.pc ; do \
		rm -f "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; \
		${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}/pkgconfig" ; done

install-includes:
	@-rm -f "${DESTDIR}${INCLUDEDIR}/libr/sflib"
	@-rm -f "${DESTDIR}${INCLUDEDIR}/libr"
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr"
	(cd include && for FILE in *.h ; do ${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr" ; done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib"
	(cd include/sflib && for DIR in * ; do \
		${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$DIR" ; \
		for FILE in $$DIR/*.h ; do \
			${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$FILE" ; \
		done ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sdb"
	(cd include/sdb && for FILE in * ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/sdb/$$FILE" ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/r_util"
	(cd include/r_util && for FILE in * ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/r_util/$$FILE" ; \
	done)

symstall install-symlink:
	mkdir -p "${DESTDIR}${BINDIR}" \
		"${DESTDIR}${INCLUDEDIR}" \
		"${DESTDIR}${LIBDIR}/pkgconfig" \
		"${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr" && ln -fs "${PWD}/include" "${DESTDIR}${INCLUDEDIR}/libr"
	cd ../pkgcfg && for FILE in *.pc ; do \
		if [ -e "${PWD}/../pkgcfg/$${FILE}" ] ; then \
			ln -fs "${PWD}/../pkgcfg/$${FILE}" \
				"${DESTDIR}${LIBDIR}/pkgconfig/$${FILE}" ; \
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
	@$(foreach lib,$(shell find * -type f -iname "*.${EXT_SO}" | grep -v '(lib|parse)/t/' | grep lib | grep -v /bin/ | grep -v /p/), \
	  echo " ${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  rm -f "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ${INSTALL_LIB} "$(lib)" "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ( cd "${DESTDIR}${LIBDIR}" ; ln -fs "$(call libpath-to-name-version,$(lib),${LIBVERSION})" "$(call libpath-to-name,$(lib))" ) ; \
	)
	# object archives
	@for FILE in `find * -type f -iname "*.${EXT_AR}" | grep -v fs/p` ; do \
	  echo " ${DESTDIR}${LIBDIR}/$$FILE"; ${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}" ; done || true
	# plugins
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	@for FILE in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${DESTDIR}${LIBDIR}/radare2/${VERSION}/$$FILE"; \
	  ${INSTALL_LIB} "$$FILE" "${DESTDIR}${LIBDIR}/radare2/${VERSION}" ; done
	cd "${DESTDIR}${LIBDIR}/radare2" ; ln -fs "${VERSION}" last

#@echo "lang/p/radare.* ${DESTDIR}${DESTDIR}${PREFIX}/${LIBDIR}/radare2/${VERSION}"
#${INSTALL_DATA} lang/p/radare.* ${DESTDIR}${LIBDIR}/radare2/${VERSION}

deinstall uninstall:
	# libraries
	-@for FILE in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# object archives
	-@for FILE in `find * | grep -e '\.${EXT_AR}$$'` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# includes
	-if [ -h "${DESTDIR}${INCLUDEDIR}/libr" ]; then \
		rm -f "${DESTDIR}${INCLUDEDIR}/libr" ; \
	else \
		(cd include && for FILE in * ; do rm -f "${DESTDIR}${INCLUDEDIR}/libr/$$FILE" ; done) ; \
	fi
	# programs
	-@for FILE in `find */t -perm -u+x -type f | grep 2`; do \
	FILE=`echo $$FILE|awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${BINDIR}/$$FILE" ; rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	# plugins
	-@for FILE in `find */p -perm -u+x -type f`; do \
	FILE="${DESTDIR}${LIBDIR}/radare2/${VERSION}/`echo $$FILE|awk -F / '{ print $$NF; }'`"; \
	echo $$FILE ; rm -f $$FILE ; done
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/libr.pc"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/r_"*.pc
	# test programs
	rm -rf "${DESTDIR}${BINDIR}/libr-test"
	# TODO: use for FILE in LIBS (like in binr/Makefile)
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.${LIBVERSION}"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.0"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/libr2.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr2.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/libr.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr.${EXT_AR}"
	rm -rf "${DESTDIR}${DATADIR}/doc/radare2"
	@echo libr aka radare2 has been uninstalled from PREFIX=${DESTDIR}${PREFIX}

clean:
	for LIB in ${LIBS}; do ( cd $${LIB} && ${MAKE} clean ); done

mrproper:
	rm -rf .libr libr.${LIB_SO} libr.${LIB_AR}
	for LIB in ${LIBS}; do ( cd $${LIB} && ${MAKE} mrproper ); done

.PHONY: sloc mrproper clean pkgcfg install deinstall uninstall libr
.PHONY: install-includes install-pkgconfig install-symlink all
