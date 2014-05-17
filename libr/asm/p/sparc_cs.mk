OBJ_SPARCCS=asm_sparc_cs.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_SPARCCS=../../shlr/capstone/libcapstone.a

SHARED2_SPARCCS=$(addprefix ../,${SHARED_SPARCCS})

STATIC_OBJ+=${OBJ_SPARCCS}
SHARED_OBJ+=${SHARED_SPARCCS}
TARGET_SPARCCS=asm_sparc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARCCS}

${TARGET_SPARCCS}: ${OBJ_SPARCCS}
	${CC} $(call libname,asm_sparc) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SPARCCS} ${OBJ_SPARCCS} ${SHARED2_SPARCCS}
