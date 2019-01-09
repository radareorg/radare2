CFLAGS+=-Ip/librapwrap/include
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

OBJ_RAP=debug_r2p.o 

STATIC_OBJ+=${OBJ_RAP}
TARGET_RAP=debug_r2p.${EXT_SO}

ALL_TARGETS+=${TARGET_RAP}

${TARGET_RAP}: ${OBJ_RAP}
	${CC} $(call libname,debug_r2p) ${OBJ_RAP} ${CFLAGS} ${LDFLAGS} -o ${TARGET_RAP}
