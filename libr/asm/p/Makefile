CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__

foo: all

ALL_TARGETS=
ARCHS=dummy.mk mips.mk sparc.mk java.mk bf.mk arm.mk m68k.mk ppc.mk x86bea.mk x86olly.mk x86.mk csr.mk x86nasm.mk psosvm.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

a:
	gcc -DTEST asm_x86_nasm.c `pkg-config --libs --cflags r_asm`

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

.PHONY: all clean foo
