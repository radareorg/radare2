CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/util
OBJS=code.o class.o ops.o

all: out

out: ${OBJS}
	${CC} -g ${LDFLAGS} ${CFLAGS} -I. ${OBJS} main.c -lr_util -o out

clean:
	rm -f ${OBJS} a.out
