OBJ_XCORECS=asm_xcore_cs.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_XCORECS=../../shlr/capstone/libcapstone.a

SHARED2_XCORECS=$(addprefix ../,${SHARED_XCORECS})

STATIC_OBJ+=${OBJ_XCORECS}
SHARED_OBJ+=${SHARED_XCORECS}
TARGET_XCORECS=asm_xcore_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_XCORECS}

${TARGET_XCORECS}: ${OBJ_XCORECS}
	${CC} $(call libname,asm_xcore) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_XCORECS} ${OBJ_XCORECS} ${SHARED2_XCORECS}
