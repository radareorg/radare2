OBJ_BFS=fs_bfs.o

STATIC_OBJ+=${OBJ_BFS}
TARGET_BFS=fs_bfs.${EXT_SO}

ALL_TARGETS+=${TARGET_BFS}

${TARGET_BFS}: ${OBJ_BFS}
	${CC} $(call libname,fs_bfs) ${LDFLAGS} ${CFLAGS} -o ${TARGET_BFS} ${OBJ_BFS}