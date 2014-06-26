include ../../config-user.mk
include ../../mk/${COMPILER}.mk
SHLR?=$(shell pwd)/..

OSTYPE?=$(shell uname | tr 'A-Z' 'a-z')
ifeq (${OSTYPE},)
all:
	echo LE FAIL
	exit 1
endif

ifeq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-fPIC
endif

#CFLAGS+=-g -ggdb
CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
OBJS=code.o class.o ops.o

all: out libr_java.a

libr_java.a: ${OBJS}
	rm -f libr_java.a
	${CC_AR} libr_java.a ${OBJS}
	${RANLIB} libr_java.a

out: ${OBJS} main.o
	${CC} ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.o \
		-lr_util ${SHLR}/sdb/src/libsdb.a -o out 

clean:
	rm -f ${OBJS} main.o a.out libr_java.a out
