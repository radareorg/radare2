CFLAGS+=-I$(SHLR)/windbg/
LIB_PATH=$(SHLR)/windbg/

-include ../../global.mk
-include ../../../global.mk
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/cons -lr_cons
LDFLAGS+=-L$(LTOP)/parse -lr_parse
LDFLAGS+=-L$(LTOP)/anal -lr_anal
LDFLAGS+=-L$(LTOP)/reg -lr_reg
LDFLAGS+=-L$(LTOP)/bp -lr_bp
LDFLAGS+=-L$(LTOP)/io -lr_io

include $(STOP)/windbg/deps.mk

OBJ_WINDBG=debug_windbg.o

STATIC_OBJ+=${OBJ_WINDBG}
TARGET_WINDBG=debug_windbg.${EXT_SO}

ALL_TARGETS+=${TARGET_WINDBG}

${TARGET_WINDBG}: ${OBJ_WINDBG}
	${CC} $(call libname,debug_windbg) ${OBJ_WINDBG} ${CFLAGS} ${LDFLAGS}
