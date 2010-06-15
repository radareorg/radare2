CFLAGS+=-g -Wall
PREFIX?=/usr
DESTDIR?=
PFX=${DESTDIR}${PREFIX}

all: r2rc

r2rc: r2rc.o emit_x86.o emit_x64.o out.o
	gcc -I. out.o r2rc.o emit*.o -o r2rc

test:
	./rcc t/hello.r > t/hello.S
	gcc t/hello.S -o t/hello
#	cat t/hello.S
	t/hello
	#spp test.r | ./rcc
	#./rcc test.r

install:
	chmod +x r2rc
	mkdir -p ${PFX}/bin
	cp r2rc ${PFX}/bin
	chmod +x r2rc-tool
	cp r2rc-tool ${PFX}/bin

install-symlink:
	mkdir -p ${PFX}/bin
	ln -fs ${PWD}/r2rc ${PFX}/bin/r2rc
	ln -fs ${PWD}/r2rc-tool ${PFX}/bin/r2rc-tool

deinstall uninstall:
	rm -f ${PFX}/bin/r2rc ${PFX}/bin/r2rc-tool

clean mrproper:
	cd t && ${MAKE} clean
	-rm -f r2rc r2rc.o out.o emit*.o


.PHONY: all clean install install-symlink deinstall uninstall r2rc test mrproper
