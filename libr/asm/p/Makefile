CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__

CFLAGS_IMP=-I../../include -I../arch/ -I../arch/include -w -fPIC -shared -Wl,-R..
# XXX
CFLAGS_IMP+=-DLIL_ENDIAN=1 -D__UNIX__

foo: all

ALL_TARGETS=
ARCHS=dummy.mk mips.mk sparc.mk java.mk bf.mk arm.mk m68k.mk ppc.mk x86bea.mk x86olly.mk x86.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ} \
		${OBJ_X86} ${OBJ_X86_OLLY} ${OBJ_ARM} \
		${OBJ_MIPS} ${OBJ_SPARC} ${OBJ_PPC} \
		${OBJ_BF} ${OBJ_CSR} ${OBJ_M68K} ${OBJ_JAVA}

.PHONY: all clean foo
