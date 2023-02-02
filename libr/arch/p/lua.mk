OBJ_LUA=p/lua/plugin.o

STATIC_OBJ+=$(OBJ_LUA)
TARGET_LUA=arch_lua.${EXT_SO}

ALL_TARGETS+=${TARGET_LUA}

${TARGET_LUA}: ${OBJ_LUA}
	${CC} $(LDFLAGS) ${CFLAGS} $(call libname,arch_lua) $(CS_CFLAGS) \
		-o arch_lua.${EXT_SO} ${OBJ_LUA} $(CS_LDFLAGS)
