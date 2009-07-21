include ../config-user.mk

PREFIX?=${PWD}/../prefix
PFX=${DESTDIR}${PREFIX}
#PREFIX=${PFX}

# Libraries
LIBLIST=io util lib meta lang flags bin bininfo macro hash line cons print config syscall range socket cmd asm anal parse search diff bp debug reg core var sign trace vm th db

# Under development
#LIBLIST+=print
#LIBLIST+=util
#LIBLIST+=search

# TODO : generate single library linking against the rest
#LIBSO=libr.so
#LIBAR=libr.a

all:
	echo PREFIX=${PREFIX}
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} all ); done
	@echo Build done for: ${LIBLIST}

pkgcfg:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} pkgcfg ); done
	cd asm && ${MAKE} pkgcfg NAME=libr DEPS="r_`echo ${LIBLIST}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBLIST and so :)

install:
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	echo Using prefix: ${PFX}
	# libraries
	@${INSTALL_DIR} ${PFX}/lib
	@for a in `find * | grep -e '\.so$$' | grep lib` ; do \
	echo " $$a "; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# object archives
	@for a in `find * | grep -e '\.a$$'` ; do \
	echo " $$a"; ${INSTALL_DATA} $$a ${PFX}/lib ; done
	# includes
	@${INSTALL_DIR} ${PFX}/include/libr
	(cd include && ${INSTALL_DATA} * ${PFX}/include/libr)
	# programs
	@${INSTALL_DIR} ${PFX}/bin
	@for a in `find */t -perm /u+x -type f | grep 2`; \
	do echo " $$a"; ${INSTALL_PROGRAM} $$a ${PFX}/bin ; done
	# plugins
	@${INSTALL_DIR} ${PFX}/lib/pkgconfig
	for a in ../pkgcfg/*.pc ; do ${INSTALL_DATA} $$a ${PFX}/lib/pkgconfig ; done
	#${INSTALL_DATA} libr.pc ${PFX}/lib/pkgconfig
	@${INSTALL_DIR} ${PFX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${PFX}/share/vala/vapi
	@${INSTALL_DIR} ${PFX}/lib/radare2
	@for a in `find */p -perm /u+x -type f`; \
	do echo " $$a"; ${INSTALL_DATA} $$a ${PFX}/lib/radare2 ; done
	# test programs
	@${INSTALL_DIR} ${PFX}/bin-test
	@for a in `find */t -perm /u+x -type f | grep -v 2`; \
	do echo " $$a"; ${INSTALL_PROGRAM} $$a ${PFX}/bin-test ; done
	@echo libr aka radare2 has been installed:
	@echo PREFIX=${PREFIX}
	@echo DESTDIR=${DESTDIR}
	${INSTALL_DATA} lang/p/radare.* ${PFX}/lib/radare2

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
	a="${PREFIX}/bin-test/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PREFIX}/bin-test
	@echo libr aka radare2 has been uninstalled from PREFIX=${PREFIX}

todo:
	grep -re TODO -e XXX *

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done
	cd vapi/t && ${MAKE} clean

mrproper: clean
	rm -f libr.pc
