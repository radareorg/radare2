#include ../../config.mk
#BINDEPS=r_reg r_bp r_util r_io r_anal

CFLAGS+=-I$(SHLR)/bochs/include/
LIB_PATH=$(SHRL)/bochs/

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

OBJ_BOCHS=debug_bochs.o 

STATIC_OBJ+=${OBJ_BOCHS}
TARGET_BOCHS=debug_bochs.${EXT_SO}

ALL_TARGETS+=${TARGET_BOCHS}

${TARGET_BOCHS}: ${OBJ_BOCHS}
	${CC_LIB} $(call libname,debug_bochs) ${OBJ_BOCHS} ${CFLAGS} ${LDFLAGS}
