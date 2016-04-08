include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk
OFILES=libtcc.o tccgen.o tccpp.o

CFLAGS+=${PIC_CFLAGS}

ifneq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring mingw32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
endif
endif

CFLAGS+=-fstrict-aliasing
CFLAGS+=-I../../libr/include
CFLAGS+=-Wall -g -ggdb
LDFLAGS+=-shared
ifeq (${OSNAME},darwin)
SOEXT?=dylib
else
SOEXT?=so
endif
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.a

${LIBNAME}: ${OFILES}
	${CC} -o ${LIBNAME} ${LDFLAGS} ${OFILES}

libr_tcc.a: ${OFILES}
	rm -f libr_tcc.a
	${AR} q libr_tcc.a ${OFILES}
	${RANLIB} libr_tcc.a

clean:
	rm -f ${LIBNAME} *.o *.a
