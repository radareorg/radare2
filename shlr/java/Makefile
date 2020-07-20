NAME=r_java
ifeq ($(CC),cccl)
EXT_AR=lib
else
EXT_AR=a
endif
LIBAR?=libr_java.$(EXT_AR)

include ../../config-user.mk
include ../../libr/config.mk
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
CFLAGS+=-g

CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
OBJS=code.o class.o ops.o dsojson.o

include ../../shlr/sdb.mk

all: libr_java.$(EXT_AR)

RANLIB?=ranlib

libr_java.$(EXT_AR): ${OBJS}
	rm -f libr_java.$(EXT_AR)
	${CC_AR} ${OBJS}
	${RANLIB} libr_java.$(EXT_AR)

out: ${OBJS} main.o
	echo "COMPILER: ${COMPILER} ${CC}"
	${CC} ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.o \
		-lr_util ../sdb/src/libsdb.$(EXT_AR) ${LINK} -o out

clean:
	rm -f ${OBJS} main.o a.out libr_java.$(EXT_AR) out
