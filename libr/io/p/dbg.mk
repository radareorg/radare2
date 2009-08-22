include ../../../config-user.mk

OBJ_DBG=io_dbg.o

STATIC_OBJ+=${OBJ_DBG}
TARGET_DBG=io_dbg.so

ALL_TARGETS+=${TARGET_DBG}

${TARGET_DBG}: ${OBJ_DBG}
	${CC} ${CFLAGS} -o ${TARGET_DBG} ${OBJ_DBG}
