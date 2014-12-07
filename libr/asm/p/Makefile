include ../../config.mk

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
LDFLAGS+=-L../../util -L../../lib
LDFLAGS+=${LINK} -lr_util

CURDIR=

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=mips_gnu.mk x86_cs.mk sparc_cs.mk sparc_gnu.mk java.mk bf.mk arm_gnu.mk dalvik.mk
ARCHS+=x86_as.mk x86_nz.mk cris_gnu.mk
ARCHS+=ppc_gnu.mk ppc_cs.mk x86_olly.mk x86_udis.mk csr.mk x86_nasm.mk psosvm.mk avr.mk
ARCHS+=msil.mk sh.mk arm_winedbg.mk tms320.mk gb.mk snes.mk ebc.mk malbolge.mk ws.mk
ARCHS+=6502.mk h8300.mk cr16.mk v850.mk spc700.mk propeller.mk msp430.mk i4004.mk
include $(ARCHS)

all: ${ALL_TARGETS}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
