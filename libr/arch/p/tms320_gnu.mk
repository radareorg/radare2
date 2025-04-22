OBJ_TMS320GNU=p/tms320/plugin_gnu.o
OBJ_TMS320GNU+=p/tms320/gnu/tic30-dis.o
OBJ_TMS320GNU+=p/tms320/gnu/tic4x-dis.o
OBJ_TMS320GNU+=p/tms320/gnu/tic54x-dis.o
OBJ_TMS320GNU+=p/tms320/gnu/tic54x-opc.o
OBJ_TMS320GNU+=p/tms320/gnu/tic6x-dis.o

STATIC_OBJ+=${OBJ_TMS320GNU}
TARGET_TMS320GNU=arch_tms320_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_TMS320GNU}

${TARGET_TMS320GNU}: ${OBJ_TMS320GNU}
	${CC} $(call libname,arch_tms320_gnu) ${CFLAGS} \
		-o arch_tms320_gnu.${EXT_SO} ${OBJ_TMS320GNU}
