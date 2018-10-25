#include ../../config.mk
#BINDEPS=r_reg r_bp r_util r_io r_anal

CFLAGS+=-I$(SHLR)/qnx/include/
LIB_PATH=$(SHRL)/qnx/

ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

-include ../../global.mk
-include ../../../global.mk

-include $(STOP)/qnx/deps.mk

LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/cons -lr_cons
LDFLAGS+=-L$(LTOP)/parse -lr_parse
LDFLAGS+=-L$(LTOP)/anal -lr_anal
LDFLAGS+=-L$(LTOP)/reg -lr_reg
LDFLAGS+=-L$(LTOP)/bp -lr_bp
LDFLAGS+=-L$(LTOP)/io -lr_io

OBJ_QNX=debug_qnx.o 

STATIC_OBJ+=${OBJ_QNX}
TARGET_QNX=debug_qnx.${EXT_SO}

ALL_TARGETS+=${TARGET_QNX}

${TARGET_QNX}: ${OBJ_QNX}
	${CC} $(call libname,debug_qnx) ${OBJ_QNX} ${CFLAGS} ${LDFLAGS}
