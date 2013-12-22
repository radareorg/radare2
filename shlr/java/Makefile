include ../../config-user.mk
include ../../mk/${COMPILER}.mk
SHLR?=$(shell pwd)/..

#CFLAGS+=-g -ggdb -fPIC
CFLAGS+=-fPIC
CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
LDFLAGS+=-L../../libr/sdb
OBJS=code.o class.o ops.o

all: out

out: ${OBJS}
	${CC} -g ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.c -lr_util ${SHLR}/sdb/src/libsdb.a -o out 

clean:
	rm -f ${OBJS} a.out
