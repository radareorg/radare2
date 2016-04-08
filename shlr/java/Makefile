NAME=r_java
LIBAR?=libr_java.a

include ../../config-user.mk
include ../../global.mk
include ../../mk/platform.mk
_INCLUDE_MK_GCC_=
include ../../mk/${COMPILER}.mk
SHLR?=..
include ../zip/deps.mk

OSTYPE?=$(shell uname | tr 'A-Z' 'a-z')
ifeq (${OSTYPE},)
all:
	echo "OSTYPE not defined"
	exit 1
endif

CFLAGS+=${PIC_CFLAGS}
ifneq (,$(findstring mingw32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
endif

CFLAGS+=-g -ggdb
CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
OBJS=code.o class.o ops.o dsojson.o

all: libr_java.a

RANLIB?=ranlib

libr_java.a: ${OBJS}
	rm -f libr_java.a
	${CC_AR} ${OBJS}
	${RANLIB} libr_java.a

out: ${OBJS} main.o
	echo "COMPILER: ${COMPILER} ${CC}"
	${CC} ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.o \
		-lr_util ../sdb/src/libsdb.a ${LINK} -o out

clean:
	rm -f ${OBJS} main.o a.out libr_java.a out
