CFLAGS+=-I../../libr/include
OBJS=code.o class.o ops.o

all: out

out: ${OBJS}
	${CC} -g ${CFLAGS} -I. ${OBJS} main.c -lr_util -o out

clean:
	rm -f ${OBJS} a.out
