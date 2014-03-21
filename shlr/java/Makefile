include ../../config-user.mk
include ../../mk/${COMPILER}.mk
SHLR?=$(shell pwd)/..

#CFLAGS+=-g -ggdb -fPIC
CFLAGS+=-g
CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
LDFLAGS+=-L../../libr/sdb
OBJS=code.o class.o ops.o

all: out

out: ${OBJS} main.o
	${CC} ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.o \
		-lr_util ${SHLR}/sdb/src/libsdb.a -o out 

clean:
	rm -f ${OBJS} main.o a.out
