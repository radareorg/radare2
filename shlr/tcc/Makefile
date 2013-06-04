include ../../config-user.mk
include ../../mk/gcc.mk
#OFILES=i386-asm.o i386-gen.o libtcc.o tccasm.o tccelf.o tccgen.o tccpp.o 
OFILES=i386-asm.o i386-gen.o libtcc.o tccasm.o tccelf.o tccgen.o tccpp.o 

CFLAGS+=-fPIC
LDFLAGS=-shared
SOEXT?=dylib
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.a

${LIBNAME}: ${OFILES}
	${CC} -o ${LIBNAME} ${LDFLAGS} ${OFILES}

libr_tcc.a: ${OFILES}
	ar -r libr_tcc.a ${OFILES}
	ranlib libr_tcc.a

clean:
	rm -f ${LIBNAME} *.o *.a
