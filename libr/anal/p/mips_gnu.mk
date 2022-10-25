N=anal_mips_gnu
OBJ_MIPS=$(N).o
# OBJ_MIPS+=../../asm/arch/mips/mipsasm.o
OBJ_MIPS+=../../asm/arch/mips/gnu/mips-dis.o
OBJ_MIPS+=../../asm/arch/mips/gnu/mips16-opc.o
OBJ_MIPS+=../../asm/arch/mips/gnu/micromips-opc.o
OBJ_MIPS+=../../asm/arch/mips/gnu/mips-opc.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_MIPS}
TARGET_MIPS=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,$(N)) ${CFLAGS} ${CS_CFLAGS} \
		-o $(TARGET_MIPS) ${OBJ_MIPS} ${CS_LDFLAGS}
