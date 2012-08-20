include ../../config.mk

CFLAGS+=-I../../include

HOST_CC=gcc

all: tree.o

tree.o: lex.yy.o

cparse.o: lemon
	./lemon cparse.y
	${CC} ${CFLAGS} -c cparse.c

lex.yy.o: cparse.o
	${FLEX} cparse.l
	${CC} ${CFLAGS} -c lex.yy.c

lemon.o:
	${HOST_CC} ${CFLAGS} -c lemon.c

lemon: lemon.o
	${HOST_CC} lemon.o -o lemon

clean:
	rm -f *.o lemon cparse.c cparse.out lex.yy.c
