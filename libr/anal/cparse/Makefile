include ../../config.mk

CFLAGS+=-I../../include

HOST_CC=gcc

ifeq ($(HAVE_CPARSE),1)
all: tree.o
else
all:
endif

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

gen.o     : gen.c gen.h
error.o   : error.c error.h gen.h
symset.o  : symset.c symset.h gen.h
pplex.o   : pplex.c pplex.h gen.h error.h
exptree.o : exptree.c exptree.h gen.h error.h symset.h pplex.h
pp.o      : pp.c pp.h gen.h error.h symset.h pplex.h exptree.h

clean:
	rm -f *.o lemon cparse.c cparse.h cparse.out lex.yy.c *.d
