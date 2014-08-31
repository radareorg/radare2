include ../../../config-user.mk
include ../../../libr/config.mk
include ../../../mk/${COMPILER}.mk

ifneq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring ming32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
CFLAGS+=-fPIC
LDFLAGS_SHARED?=-fPIC -shared
endif
endif
ifeq (${OSTYPE},windows)
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-fPIC -shared
else
ifeq (${OSTYPE},darwin)
EXT_SO=dylib
SOVER=${EXT_SO}
LDFLAGS+=-dynamic
LDFLAGS_SHARED?=-fPIC -shared
# ifeq (${ARCH},i386)
   #CC+=-arch i386
#   CC+=-arch x86_64
# endif
else
SOVERSION=0
EXT_SO=so
SOVER=${EXT_SO}
LDFLAGS_SHARED+=-Wl,-soname,libr_z.${EXT_SO}
endif
endif

OBJS = adler32.o crc32.o deflate.o infback.o \
	inffast.o inflate.o inftrees.o trees.o \
	zutil.o compress.o uncompr.o gzclose.o \
	gzlib.o gzread.o gzwrite.o

#OFILES= libr_z.a $(OBJS)
OFILES= $(OBJS)

CFLAGS+=-Wall
CFLAGS+=-I../../libr/include -I../include/
#LDFLAGS+=-L../../../libr/util
LIBNAME=libr_z.${SOVER}
LIBAR=libr_z.a

all: ${LIBNAME} ${LIBAR}

${LIBNAME}: ${OBJS}
ifneq ($(SILENT),)
	@echo LIB ${LIBNAME}
endif
	${CC} ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${OBJS}

libr_z.a: ${OFILES}
	${CC_AR} ${OFILES}
	${RANLIB} libr_z.a

clean:
	rm -f ${LIBNAME} *.o *.a *.d *.dylib *.so
