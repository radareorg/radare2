OBJ=radare2.o
BIN=radare2
BINDEPS=r_core r_cons r_macro r_util r_flags r_lib r_io r_hash r_cmd r_config r_asm r_lang r_debug r_print r_line r_bin

#LIBS=-lr_core -L..
### shared
#LIBS=../*.o \
#  -Wl,-R../../config/ \
#  -Wl,-R../../cons/ \
#  -Wl,-R../../line/ \
#  -Wl,-R../../io/ \
#  -Wl,-R../../cmd/ \
#  -Wl,-R../../util/ \
#  -Wl,-R../../print/ \
#  -Wl,-R../../flags/ \
#  -Wl,-R../../asm/ \
#  -Wl,-R../../lib/ \
#  -Wl,-R../../macro/ \
#  -Wl,-R../../debug/ \
#  -Wl,-R../../hash/ \
#  -Wl,-R../../bin/ \
#  -Wl,-R../../lang/ \
#  -Wl,-R../ \
#  -L../../config/ \
#  -L../../cons/ \
#  -L../../lang/ \
#  -L../../line/ \
#  -L../../io/ \
#  -L../../cmd/ \
#  -L../../util/ \
#  -L../../print/ \
#  -L../../flags/ \
#  -L../../asm/ \
#  -L../../lib/ \
#  -L../../macro/ \
#  -L../../debug/ \
#  -L../../hash/ \
#  -L../../bin/ \
#  -L../ \
#  -lr_core -lr_config -lr_cons -lr_line -lr_cmd -lr_util -lr_print \
#  -lr_flags -lr_asm -lr_lib -lr_macro -lr_debug -lr_bin -lr_io -lr_hash -lr_lang
LIBS+=-ldl

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
LIBS+=-ldl

include ../../rules.mk
