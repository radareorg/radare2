OBJ_LUA=bin_lua.o ../format/lua/lua.o

STATIC_OBJ+=${OBJ_LUA}
TARGET_LUA=bin_lua.${EXT_SO}

ALL_TARGETS+=${TARGET_LUA}

${TARGET_LUA}: ${OBJ_LUA}
	${CC} $(call libname,bin_lua) -shared ${CFLAGS} \
		-o ${TARGET_LUA} ${OBJ_LUA} $(LINK) $(LDFLAGS)
