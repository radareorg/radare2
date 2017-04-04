OBJ_LUA53=bin_lua53.o

STATIC_OBJ+=${OBJ_LUA53}
TARGET_LUA53=bin_lua53.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_LUA53}

${TARGET_LUA53}: ${OBJ_LUA53}
	-${CC} $(call libname,bin_lua53) -shared ${CFLAGS} \
	$(OBJ_LUA53) $(LINK) $(LDFLAGS)
endif
