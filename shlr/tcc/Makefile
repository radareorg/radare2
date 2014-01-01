include ../../config-user.mk
include ../../mk/${COMPILER}.mk
OFILES=libtcc.o tccgen.o tccpp.o

CFLAGS+=-fPIC -Wall
LDFLAGS+=-shared
SOEXT?=dylib
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.a

${LIBNAME}: ${OFILES}
	${CC} -o ${LIBNAME} ${LDFLAGS} ${OFILES}

libr_tcc.a: ${OFILES}
	${AR} q libr_tcc.a ${OFILES}
	${RANLIB} libr_tcc.a

clean:
	rm -f ${LIBNAME} *.o *.a
