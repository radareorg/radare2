CFLAGS+=-Ip/librapwrap/include
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

OBJ_RAP=debug_rap.o 
#librapwrap/rapwrapper.o

#librapwrap/rapwrapper.o:
#	${CC} -c ${CFLAGS} ${LDFLAGS} -o p/librapwrap/rapwrapper.o p/librapwrap/rapwrapper.c

STATIC_OBJ+=${OBJ_RAP}
TARGET_RAP=debug_rap.${EXT_SO}

ALL_TARGETS+=${TARGET_RAP}

${TARGET_RAP}: ${OBJ_RAP}
	${CC} -shared ${OBJ_RAP} ${CFLAGS} ${LDFLAGS} -o ${TARGET_RAP}
