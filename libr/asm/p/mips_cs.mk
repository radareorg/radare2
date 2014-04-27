# capstone

OBJ_MIPSCS=asm_mips_cs.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_MIPSCS=../../shlr/capstone/libcapstone.a

SHARED2_MIPSCS=$(addprefix ../,${SHARED_MIPSCS})

STATIC_OBJ+=${OBJ_MIPSCS}
SHARED_OBJ+=${SHARED_MIPSCS}
TARGET_MIPSCS=asm_mips_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPSCS}

${TARGET_MIPSCS}: ${OBJ_MIPSCS}
	${CC} $(call libname,asm_mips) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_MIPSCS} ${OBJ_MIPSCS} ${SHARED2_MIPSCS}
