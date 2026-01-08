NAME=r_java

include ../../config-user.mk
include ../../mk/${COMPILER}.mk
include ../../libr/config.mk
include ../../global.mk
include ../../mk/platform.mk
_INCLUDE_MK_GCC_=
include ../../mk/${COMPILER}.mk
SHLR?=..
LIBAR=libr_java.$(EXT_AR)
CC_AR=$(AR) -r $(LIBAR)

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
# CFLAGS+=-g

CFLAGS:=-I../../libr/include $(CFLAGS)
LDFLAGS+=-L../../libr/util
OBJS=code.o class.o ops.o

all: $(LIBAR)

include ../../shlr/sdb.mk
include ../zip/deps.mk

RANLIB?=ranlib

$(LIBAR): ${OBJS}
	rm -f libr_java.$(EXT_AR)
	${CC_AR} ${OBJS}
	${RANLIB} libr_java.$(EXT_AR)

out: ${OBJS} main.o
	echo "COMPILER: ${COMPILER} ${CC}"
	${CC} ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.o \
		-lr_util ../sdb/src/libsdb.$(EXT_AR) ${LINK} -o out

clean:
	rm -f ${OBJS} main.o a.out $(LIBAR) out
