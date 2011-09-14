#CC=i386-mingw32-gcc
SRC= regcomp.c	regerror.c	regexec.c	
CFLAGS+=-I.
CFLAGS+=-I../../include
#CFLAGS+=-Wall
#CFLAGS+=`pkg-config --cflags --libs r_util`

# implicit engine.c	
all:
	${CC} ${CFLAGS} test.c ${SRC}

clean:
	rm -f *.o
