include ../../config.mk

CFLAGS=-I../../include -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
CFLAGS+=-L../../util -lr_util -L../../reg -lr_reg -L.. -lr_core
CFLAGS+=-L../../db -lr_db -L../../cons -lr_cons -L../../bin -lr_bin
CFLAGS+=-L../../parse -lr_parse -L../../io -lr_io -L../../fs -lr_fs
CFLAGS+=-L../../magic -lr_magic -L../../hash -lr_hash -L../../config -lr_config
CFLAGS+=-L../../anal -lr_anal -L../../egg -lr_egg -L../../flags -lr_flags
CFLAGS+=-L../../syscall -lr_syscall -L../../socket -lr_socket -L../../search -lr_search
CFLAGS+=-L../../diff -lr_diff -L../../lang -lr_lang -L../../debug -lr_debug
CFLAGS+=-L../../bp -lr_bp -L../../reg -lr_reg -L../../asm -lr_asm
CFLAGS+=../../../shlr/sdb/src/libsdb.a
CFLAGS+=../../../shlr/zip/librz.a
CFLAGS+=../../../shlr/gdb/lib/libgdbr.a
CFLAGS+=../../../shlr/wind/libr_wind.a
#CFLAGS+=-L../../anal -lr_anal -L../../core -lr_core
LDFLAGS+=${LINK}

foo: all

ALL_TARGETS=
PLUGS=java.mk anal.mk

include $(PLUGS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
