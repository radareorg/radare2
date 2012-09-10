include ../../config.mk

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
LDFLAGS+=-L../../util -L../../lib
LDFLAGS+=${LINK} -lr_util

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=mips.mk sparc.mk java.mk bf.mk arm.mk dalvik.mk x86_as.mk x86_nz.mk
ARCHS+=ppc.mk x86_olly.mk x86.mk csr.mk x86_nasm.mk psosvm.mk avr.mk
ARCHS+=msil.mk sh.mk arm_winedbg.mk
include $(ARCHS)

all: ${ALL_TARGETS}

a:
	${CC} -DTEST asm_x86_nasm.c `pkg-config --libs --cflags r_asm` -o a${EXT_EXE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
