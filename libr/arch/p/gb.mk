OBJ_GB=p/gb/plugin.o

STATIC_OBJ+=${OBJ_GB}
TARGET_GB=gb.${EXT_SO}

ALL_TARGETS+=${TARGET_GB}

# CFLAGS += -Iarch

${TARGET_GB}: ${OBJ_GB}
	${CC} $(call libname,gb) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_GB} ${OBJ_GB}
