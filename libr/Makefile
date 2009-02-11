# XXX
PREFIX=../prefix

# Libraries
LIBLIST=io util lib lang flags bin macro hash line cons line print config syscall range socket cmd asm search diff debug reg core


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
	@mkdir -p ${PREFIX}/include
	cp -f include/* ${PREFIX}/include
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

todo:
	grep -re TODO *

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done
