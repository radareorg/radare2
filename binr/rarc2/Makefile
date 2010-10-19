include ../../config-user.mk
include ../../libr/config.mk

CFLAGS+=-g -Wall
PFX=${DESTDIR}${PREFIX}

OBJS=rarc2.o emit_x86.o emit_x64.o emit_arm.o out.o

all: config.h rarc2${EXT_EXE}

config.h:
	cp -f config.def.h config.h

rarc2${EXT_EXE}: ${OBJS}
	${CC} ${LDFLAGS} -I. ${OBJS} -o rarc2${EXT_EXE}

test:
	# only works with att mode
	./rarc2 t/hello.r > t/hello.S
	gcc t/hello.S -o t/hello
#	cat t/hello.S
	t/hello
	#spp test.r | ./rarc2
	#./rarc2 test.r

install:
	chmod +x rarc2
	mkdir -p ${PFX}/bin
	cp rarc2 ${PFX}/bin
	chmod +x rarc2-tool
	cp rarc2-tool ${PFX}/bin

install-symlink:
	mkdir -p ${PFX}/bin
	ln -fs ${PWD}/rarc2 ${PFX}/bin/rarc2
	ln -fs ${PWD}/rarc2-tool ${PFX}/bin/rarc2-tool

deinstall uninstall:
	rm -f ${PFX}/bin/rarc2 ${PFX}/bin/rarc2-tool

clean:
	cd t && ${MAKE} clean
	-rm -f rarc2 rarc2.o out.o emit*.o

mrproper: clean
	-rm -f config.h

.PHONY: all clean install install-symlink deinstall uninstall test mrproper
