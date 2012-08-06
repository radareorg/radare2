OBJ_X86_UDIS86=anal_x86_udis86.o
SHARED_X86_UDIS86=../../shrl/udis86/decode.o
SHARED_X86_UDIS86+=../../shrl/udis86/input.o
SHARED_X86_UDIS86+=../../shrl/udis86/itab.o
SHARED_X86_UDIS86+=../../shrl/udis86/syn-att.o
SHARED_X86_UDIS86+=../../shrl/udis86/syn-intel.o
SHARED_X86_UDIS86+=../../shrl/udis86/syn.o
SHARED_X86_UDIS86+=../../shrl/udis86/udis86.o

STATIC_OBJ+=${OBJ_X86_UDIS86}
SHARED_OBJ+=${SHARED_X86_UDIS86}
TARGET_X86_UDIS86=anal_x86_udis86.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_UDIS86}
CFLAGS+=-I../asm/arch/x86/udis86 -I../../asm/arch/x86/udis86

${TARGET_X86_UDIS86}: ${OBJ_X86_UDIS86}
	${CC} ${CFLAGS} $(call libname,anal_x86) -o anal_x86_udis86.${EXT_SO} ${OBJ_X86_UDIS86}
