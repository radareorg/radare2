NAME=r_lib
DEPS=r_util
OBJS=lib.o

include ../config.mk

# XXX only for linux
CFLAGS+=-Wall -DLIBR_PLUGINS=\"${LIBDIR}/radare2\"

LDFLAGS+=${DL_LIBS}

include ../rules.mk
