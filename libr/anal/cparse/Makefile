include ../../config.mk

CFLAGS+=-I../../include

HOST_CC=gcc

all: tree.o

tree.o: lex.yy.o

lex.yy.o: cparse.o
	flex cparse.l
	${CC} ${CFLAGS} -c lex.yy.c

cparse.o: lemon
	./lemon cparse.y
	${CC} ${CFLAGS} -c cparse.c

lemon: lemon.o
	${HOST_CC} lemon.o -o lemon

clean:
	rm -f *.o lemon cparse.c cparse.out lex.yy.c
