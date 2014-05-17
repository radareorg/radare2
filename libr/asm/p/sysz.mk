OBJ_SYSZCS=asm_sysz.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_SYSZCS=../../shlr/capstone/libcapstone.a

SHARED2_SYSZCS=$(addprefix ../,${SHARED_SYSZCS})

STATIC_OBJ+=${OBJ_SYSZCS}
SHARED_OBJ+=${SHARED_SYSZCS}
TARGET_SYSZCS=asm_sysz.${EXT_SO}

ALL_TARGETS+=${TARGET_SYSZCS}

${TARGET_SYSZCS}: ${OBJ_SYSZCS}
	${CC} $(call libname,asm_sysz) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SYSZCS} ${OBJ_SYSZCS} ${SHARED2_SYSZCS}
