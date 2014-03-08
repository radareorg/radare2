include ../../config-user.mk
include ../../mk/${COMPILER}.mk
OFILES=libtcc.o tccgen.o tccpp.o

CFLAGS+=-I../../libr/include
CFLAGS+=-fPIC -Wall
LDFLAGS+=-shared
ifeq ($(OSNAME),darwin)
SOEXT?=dylib
else
SOEXT?=so
endif
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.a

${LIBNAME}: ${OFILES}
	${CC} -o ${LIBNAME} ${LDFLAGS} ${OFILES}

libr_tcc.a: ${OFILES}
	${AR} q libr_tcc.a ${OFILES}
	${RANLIB} libr_tcc.a

clean:
	rm -f ${LIBNAME} *.o *.a
