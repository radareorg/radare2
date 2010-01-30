include ../global.mk
include config.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}${PREFIX}
#PREFIX=${PFX}

# Libraries
LIBLIST=util lib io meta lang flags bin bininfo macro hash line cons print config syscall range socket cmd asm anal parse search diff bp reg debug core var sign trace vm th db

# Under development
#LIBLIST+=print
#LIBLIST+=util
#LIBLIST+=search

# TODO : generate single library linking against the rest
#LIBSO=libr.so
#LIBAR=libr.a

all: libs libr

libs:
	@for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} all ); done
	@echo Build done for: ${LIBLIST}

libr: .objs libr2.${EXT_SO} libr2.${EXT_AR}

ifeq ($(WITHPIC),1)
libr2.${EXT_SO}:
	${CC} -shared ${PIC_CFLAGS} .objs/*.o -o libr2.${EXT_SO}

libr2.${EXT_AR}:
	@echo No archive libr.a. Try --without-pic in configure

else
libr2.${EXT_SO}:

libr2.${EXT_AR}:
	ar -r libr2.${EXT_AR} .objs/*.o
endif

# XXX needs autodetection of deps to remake and so..
.objs:
	mkdir -p .objs
	-for a in ${LIBLIST} ; do \
		(cd .objs && ar x ../$$a/libr_$$a.a) ; \
	done

pkgcfg:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} pkgcfg ); done
	cd asm && ${MAKE} pkgcfg NAME=libr DEPS="r_`echo ${LIBLIST}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBLIST and so :)

install-vapi:
	@${INSTALL_DIR} ${PFX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${PFX}/share/vala/vapi

install-pkgconfig:
	@${INSTALL_DIR} ${PFX}/lib/pkgconfig
	for a in ../pkgcfg/*.pc ; do ${INSTALL_DATA} $$a ${PFX}/lib/pkgconfig ; done

install-includes:
	@${INSTALL_DIR} ${PFX}/include/libr
	(cd include && ${INSTALL_DATA} * ${PFX}/include/libr)

install: install-includes install-vapi install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} ${PFX}/lib
	@for a in `find * | grep -e '\.so$$' | grep lib` ; do \
	echo "$$a ${PFX}/lib"; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# object archives
	@for a in `find * | grep -e '\.a$$'` ; do \
	echo "$$a ${PFX}/lib"; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# programs
	@${INSTALL_DIR} ${PFX}/bin
	@for a in `find */t -perm /u+x -type f | grep 2`; \
	do echo "$$a ${PFX}/bin"; ${INSTALL_PROGRAM} $$a ${PFX}/bin ; done
	# plugins
	#${INSTALL_DATA} libr.pc ${PFX}/lib/pkgconfig
	@${INSTALL_DIR} ${PFX}/lib/radare2
	@for a in `find */p -perm /u+x -type f`; \
	do echo "$$a ${PFX}/lib/radare2"; \
	${INSTALL_DATA} $$a ${PFX}/lib/radare2 ; done
	# test programs
	@${INSTALL_DIR} ${PFX}/bin/libr-test
	@for a in `find */t -perm /u+x -type f | grep -v 2`; \
	  do echo "$$a ${PFX}/bin/libr-test"; \
	  ${INSTALL_PROGRAM} $$a ${PFX}/bin/libr-test ; done
	${INSTALL_DATA} lang/p/radare.* ${PFX}/lib/radare2
	echo "lang/p/radare.* ${PFX}/lib/radare2"

deinstall uninstall:
	# libraries
	-@for a in `find * | grep -e '\.so$$' | grep lib` ; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PREFIX}/lib/$$a ; rm -f ${PREFIX}/lib/$$a ; done
	### object archives
	-@for a in `find * | grep -e '\.a$$'` ; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PREFIX}/lib/$$a ; rm -f ${PREFIX}/lib/$$a ; done
	### includes
	-(cd include && for a in * ; do rm -f ${PREFIX}/libr/$$a ; done)
	cd vapi/ ; for a in *.vapi *.deps ; do rm -f ${PREFIX}/share/vala/vapi/$$a ; done
	### programs
	-@for a in `find */t -perm /u+x -type f | grep 2`; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PREFIX}/bin/$$a ; rm -f ${PREFIX}/bin/$$a ; done
	# plugins
	-@for a in `find */p -perm /u+x -type f`; do \
	a="${PREFIX}/lib/radare2/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PREFIX}/lib/radare2
	rm -f ${PREFIX}/lib/pkgconfig/libr.pc
	rm -f ${PREFIX}/lib/pkgconfig/r_*.pc
	# test programs
	-@for a in `find */t -perm /u+x -type f | grep -v 2`; do \
	a="${PREFIX}/bin/libr-test/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PREFIX}/bin/libr-test
	@echo libr aka radare2 has been uninstalled from PREFIX=${PREFIX}

todo:
	grep -re TODO -e XXX *

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done
	cd vapi/t && ${MAKE} clean
	rm -rf .objs

mrproper: clean
	rm -f libr.pc

sloc:
	${MAKE} -C .. sloc SLOCDIR=libr

.PHONY: sloc mrproper clean todo all pkgcfg install deinstall uninstall libr
