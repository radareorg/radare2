OBJ_PYC=bin_pyc.o
OBJ_PYC+=../format/pyc/marshal.o
OBJ_PYC+=../format/pyc/pyc_magic.o
OBJ_PYC+=../format/pyc/pyc.o

STATIC_OBJ+=${OBJ_PYC}
TARGET_PYC=bin_pyc.${EXT_SO}
CFLAGS+=-I../format/pyc/

ALL_TARGETS+=${TARGET_PYC}

${TARGET_PYC}: ${OBJ_PYC}
	${CC} ${CFLAGS} -o ${TARGET_PYC} ${OBJ_PYC} $(R2_CFLAGS) $(R2_LDFLAGS) -lr_util

