OBJ_LUA_PSEUDO+=$(LIBR)/arch/p/lua/pseudo.o

TARGET_LUA_PSEUDO=parse_lua_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_LUA_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LUA_PSEUDO}
${TARGET_LUA_PSEUDO}: ${OBJ_LUA_PSEUDO}
	${CC} $(call libname,parse_lua_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_LUA_PSEUDO} ${OBJ_LUA_PSEUDO}
endif
