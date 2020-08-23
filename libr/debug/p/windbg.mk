CFLAGS+=-I$(SHLR)/winkd/
LIB_PATH=$(SHLR)/winkd/

-include ../../global.mk
-include ../../../global.mk
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/cons -lr_cons
LDFLAGS+=-L$(LTOP)/parse -lr_parse
LDFLAGS+=-L$(LTOP)/anal -lr_anal
LDFLAGS+=-L$(LTOP)/reg -lr_reg
LDFLAGS+=-L$(LTOP)/bp -lr_bp
LDFLAGS+=-L$(LTOP)/io -lr_io

include $(STOP)/winkd/deps.mk

OBJ_WINKD=debug_winkd.o

STATIC_OBJ+=${OBJ_WINKD}
TARGET_WINKD=debug_winkd.${EXT_SO}

ALL_TARGETS+=${TARGET_WINKD}

${TARGET_WINKD}: ${OBJ_WINKD}
	${CC} $(call libname,debug_winkd) ${OBJ_WINKD} ${CFLAGS} ${LDFLAGS}
