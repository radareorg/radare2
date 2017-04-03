OBJ_LUA53=anal_lua53.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=$(OBJ_LUA53)
TARGET_LUA53=anal_lua53.${EXT_SO}

ALL_TARGETS+=${TARGET_LUA53}

${TARGET_LUA53}: ${OBJ_LUA53}
	${CC} ${CFLAGS} $(call libname,anal_lua53) $(CS_CFLAGS) \
		-o anal_LUA53.${EXT_SO} ${OBJ_LUA53} $(CS_LDFLAGS)
