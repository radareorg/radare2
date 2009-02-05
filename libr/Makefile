# XXX
PREFIX=/tmp/libr-install

# Libraries
LIBLIST=io io/plugins util bin macro hash print config flags cons line lib syscall range socket cmd asm search core diff debug reg


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
	@for a in `find * | grep -e '\.so$$'` ; do \
	echo " $$a "; cp $$a ${PREFIX}/lib ; done
	# object archives
	@for a in `find * | grep -e '\.a$$'` ; do \
	echo " $$a"; cp $$a ${PREFIX}/lib ; done
	# includes
	@mkdir -p ${PREFIX}/include
	cp -f include/* ${PREFIX}/include
	# programs
	@mkdir -p ${PREFIX}/bin
	cp -f util/t/rax2 ${PREFIX}/bin
	# test programs
	@mkdir -p ${PREFIX}/bin-test
	@for a in `find */t -perm /u+x -type f`; \
	do echo " $$a"; cp $$a ${PREFIX}/bin-test ; done
	@echo libr aka radare2 has been installed in PREFIX=${PREFIX}

todo:
	grep -re TODO *

clean:
	for lib in ${LIBLIST}; do ( cd $${lib} && ${MAKE} clean ); done
