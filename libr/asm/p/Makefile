include ../../config.mk

CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
CFLAGS+=-L../../util -lr_util

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=dummy.mk mips.mk sparc.mk java.mk bf.mk arm.mk
ARCHS+=ppc.mk x86_olly.mk x86.mk csr.mk x86_nasm.mk psosvm.mk avr.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

a:
	${CC} -DTEST asm_x86_nasm.c `pkg-config --libs --cflags r_asm` -o a${EXT_EXE}

clean:
	-rm -f *.${LIB_SO} *.o ${STATIC_OBJ}

.PHONY: all clean foo
