OBJ_TMS320=p/tms320/plugin.o
OBJ_TMS320+=p/tms320/tms320_dasm.o
OBJ_TMS320+=p/tms320/c55x_plus/ins.o
OBJ_TMS320+=p/tms320/c55x_plus/c55plus.o
OBJ_TMS320+=p/tms320/c55x_plus/c55plus_decode.o
OBJ_TMS320+=p/tms320/c55x_plus/decode_funcs.o
OBJ_TMS320+=p/tms320/c55x_plus/utils.o
OBJ_TMS320+=p/tms320/c55x_plus/hashtable.o
OBJ_TMS320+=p/tms320/c55x_plus/hashvector.o


STATIC_OBJ+=${OBJ_TMS320}
TARGET_TMS320=tms320.${EXT_SO}

ALL_TARGETS+=${TARGET_TMS320}

${TARGET_TMS320}: ${OBJ_TMS320} ${SHARED_OBJ}
	${CC} $(call libname,tms320) ${CFLAGS} \
		-I../../include/ -o ${TARGET_TMS320} ${OBJ_TMS320}
