# XXX
PREFIX=../prefix

# Libraries
LIBLIST=io util lib meta lang flags bin macro hash line cons line print config syscall range socket cmd asm anal parse search diff debug reg core var


# Under development
#LIBLIST+=print
#LIBLIST+=util
#LIBLIST+=search

# TODO : generate single library linking against the rest
#LIBSO=libr.so
#LIBAR=libr.a

all:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} all ); done
	@echo Build done for: ${LIBLIST}

install:
	# libraries
	@mkdir -p ${PREFIX}/lib
	@for a in `find * | grep -e '\.so$$' | grep lib` ; do \
	echo " $$a "; cp $$a ${PREFIX}/lib ; done
	# object archives
	@for a in `find * | grep -e '\.a$$'` ; do \
	echo " $$a"; cp $$a ${PREFIX}/lib ; done
	# includes
	@mkdir -p ${PREFIX}/include/libr
	(cd include && cp -f * ${PREFIX}/include/libr)
	# programs
	@mkdir -p ${PREFIX}/bin
	@for a in `find */t -perm /u+x -type f | grep 2`; \
	do echo " $$a"; cp $$a ${PREFIX}/bin ; done
	# plugins
	@mkdir -p ${PREFIX}/lib/radare2
	@for a in `find */p -perm /u+x -type f`; \
	do echo " $$a"; cp $$a ${PREFIX}/lib/radare2 ; done
	# test programs
	@mkdir -p ${PREFIX}/bin-test
	@for a in `find */t -perm /u+x -type f | grep -v 2`; \
	do echo " $$a"; cp $$a ${PREFIX}/bin-test ; done
	@echo libr aka radare2 has been installed in PREFIX=${PREFIX}

uninstall:
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
	### programs
	-@for a in `find */t -perm /u+x -type f | grep 2`; do \
	a=`echo $$a|awk -F / '{ print $$NF; }'`; \
	echo ${PREFIX}/bin/$$a ; rm -f ${PREFIX}/bin/$$a ; done
	# plugins
	-@for a in `find */p -perm /u+x -type f`; do \
	a="${PREFIX}/lib/radare2/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PREFIX}/lib/radare2
	# test programs
	-@for a in `find */t -perm /u+x -type f | grep -v 2`; do \
	a="${PREFIX}/bin-test/`echo $$a|awk -F / '{ print $$NF; }'`"; \
	echo $$a ; rm -f $$a ; done
	rm -rf ${PREFIX}/bin-test
	@echo libr aka radare2 has been uninstalled from PREFIX=${PREFIX}

todo:
	grep -re TODO *

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done
	cd vapi/t && ${MAKE} clean
