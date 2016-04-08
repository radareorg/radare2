include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

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
else
ifneq (,$(findstring mingw64,${OSTYPE})$(findstring msys,${OSTYPE}))
LDFLAGS+=-shared
LFDLAGS_SHARE?=-shared
endif
endif
endif

CFLAGS+=-I../../libr/include
LIBAR=libr_wind.a
LDFLAGS+=-L../../libr/util
LIBS=-lr_util

OFILES=transport.o kd.o wind.o iob_pipe.o

all: libr_wind.a

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

libr_wind.a: $(OFILES)
	rm -f libr_wind.a
	${AR} q libr_wind.a ${OFILES}
	${RANLIB} libr_wind.a

clean:
	rm -f $(OBJS) libr_wind.a $(OFILES)
