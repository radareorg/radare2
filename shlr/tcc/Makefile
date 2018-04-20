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

LDFLAGS+=-L../../libr/util
LIBS+=-lr_util
CFLAGS+=-I../../libr/include

CFLAGS+=-fstrict-aliasing
CFLAGS+=-I../../libr/include
CFLAGS+=-Wall -g
LDFLAGS+=-shared
ifeq (${OSNAME},darwin)
SOEXT?=dylib
else
ifeq ($(CC),cccl)
EXT_AR=lib
SOEXT?=dll
else
EXT_AR=a
SOEXT?=so
endif
endif
LIBNAME=libr_tcc.${SOEXT}

all: ${LIBNAME} libr_tcc.$(EXT_AR)

${LIBNAME}: ${OFILES}
	${CC} $(CFLAGS) -o ${LIBNAME} ${LDFLAGS} ${LIBS} ${OFILES}

libr_tcc.$(EXT_AR): ${OFILES}
	rm -f libr_tcc.$(EXT_AR)
	${AR} q libr_tcc.$(EXT_AR) ${OFILES}
	${RANLIB} libr_tcc.$(EXT_AR)

clean:
	rm -f ${LIBNAME} *.o *.$(EXT_AR)
