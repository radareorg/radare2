OBJ_LUA_PSEUDO=$(LIBR)/arch/p/lua/pseudo.o
STATIC_OBJ+=${OBJ_LUA_PSEUDO}
TARGET_LUA_PSEUDO=parse_lua_pseudo.${EXT_SO}

ifeq ($(CC),cccl)
LUA_PSEUDO_LIBS=-L../../util -llibr_util
else
LUA_PSEUDO_LIBS=-L../../util -lr_util
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LUA_PSEUDO}
${TARGET_LUA_PSEUDO}: ${OBJ_LUA_PSEUDO}
	${CC} $(call libname,parse_lua_pseudo) $(LUA_PSEUDO_LIBS) $(LDFLAGS) $(LDFLAGS_SHARED) ${CFLAGS} -o $@ $^
endif
