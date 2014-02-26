#include ../../config.mk
#BINDEPS=r_reg r_bp r_util r_io r_anal

CFLAGS+=-I$(SHLR)/gdb/include/
LIB_PATH=$(SHRL)/gdb/

ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

-include ../../global.mk
-include ../../../global.mk
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/cons -lr_cons
LDFLAGS+=-L$(LTOP)/parse -lr_parse
LDFLAGS+=-L$(LTOP)/anal -lr_anal
LDFLAGS+=-L$(LTOP)/reg -lr_reg
LDFLAGS+=-L$(LTOP)/bp -lr_bp
LDFLAGS+=-L$(LTOP)/io -lr_io

OBJ_GDB=debug_gdb.o 

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=debug_gdb.${EXT_SO}

ALL_TARGETS+=${TARGET_GDB}

${TARGET_GDB}: ${OBJ_GDB}
	${CC_LIB} $(call libname,debug_gdb) ${OBJ_GDB} ${CFLAGS} ${LDFLAGS}
