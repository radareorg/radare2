include ../../../config-user.mk
include ../../../mk/${COMPILER}.mk


ifeq (${OS},Darwin)
SOEXT=dylib
SOVER=dylib
LDFLAGS+=-dynamic
LDFLAGS_SHARED?=-fPIC -shared
 ifeq (${ARCH},i386)
   #CC+=-arch i386 
   CC+=-arch x86_64
 endif
else
SOVERSION=0
SOEXT=so
SOVER=${SOEXT}
LDFLAGS_SHARED?=-fPIC -shared
LDFLAGS_SHARED+=-Wl,-soname,libr_z.so
endif

OBJS = adler32.o crc32.o deflate.o infback.o \
	inffast.o inflate.o inftrees.o trees.o \
	zutil.o compress.o uncompr.o gzclose.o \
	gzlib.o gzread.o gzwrite.o

OFILES= libr_z.a $(OBJS) 

CFLAGS+=-fPIC -Wall
LDFLAGS=-shared
LIBNAME=libr_z.${SOVER}

all:  ${LIBNAME} libr_z.a

${LIBNAME}: ${OBJS}
ifneq ($(SILENT),)
	@echo LIB ${LIBNAME}
endif
	${CC} ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${OBJS}
	cp ${LIBNAME} ../

libr_z.a: ${OFILES}
	${AR} q libr_z.a ${OFILES}
	${RANLIB} libr_z.a
	cp libr_z.a ../

clean:
	rm -f ${LIBNAME} *.o *.a *.d *.dylib *.so
	rm -f ../${LIBNAME} ../*.o ../*.a ../*.d ../*.dylib ../*.so
