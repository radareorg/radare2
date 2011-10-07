CFLAGS+=-Ip/libbfwbf/include
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

OBJ_BF=debug_bf.o 
#libbfwbf/bfwbfper.o

#libbfwbf/bfwbfper.o:
#	${CC} -c ${CFLAGS} ${LDFLAGS} -o p/libbfwbf/bfwbfper.o p/libbfwbf/bfwbfper.c

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=debug_bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,debug_bf) ${OBJ_BF} ${CFLAGS} ${LDFLAGS} -o ${TARGET_BF}
