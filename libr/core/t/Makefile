include ../../config.mk

OBJ=radare2.o
BIN=radare2${EXT_EXE}
BINDEPS=r_core r_cons r_macro r_util r_flags r_lib r_io r_hash r_cmd r_config r_asm r_anal
BINDEPS+=r_parse r_lang r_debug r_print r_line r_bin r_search r_meta r_bininfo r_reg r_bp r_util

CFLAGS+=-DVERSION=\"${VERSION}\"
LIBS+=${DL_LIBS}

# static
#LIBS=../*.o \
  ../../config/*.a \
  ../../cons/*.a \
  ../../line/*.a \
  ../../io/*.a \
  ../../cmd/*.a \
  ../../util/*.a \
  ../../print/*.a \
  ../../flags/*.a \
  ../../asm/*.a \
  ../../lib/*.a \
  ../../lang/*.a \
  ../../macro/*.a \
  ../../debug/*.a \
  ../../hash/*.a

include ../../rules.mk
