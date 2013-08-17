include ../../config-user.mk
include ../../mk/gcc.mk
OFILES=i386-gen.o libtcc.o tccelf.o tccgen.o tccpp.o 

CFLAGS+=-fPIC -g -ggdb
LDFLAGS=-shared -g -ggdb
SOEXT?=dylib
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.a
	${MAKE} test

test:
	gcc libr_tcc.a -I. test.c

${LIBNAME}: ${OFILES}
	${CC} -o ${LIBNAME} ${LDFLAGS} ${OFILES}

libr_tcc.a: ${OFILES}
	ar -r libr_tcc.a ${OFILES}
	ranlib libr_tcc.a

clean:
	rm -f ${LIBNAME} *.o *.a
