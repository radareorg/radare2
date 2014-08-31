#include ../../config.mk
#BINDEPS=r_reg r_bp r_util r_io r_anal

CFLAGS+=-I$(SHLR)/wind/
LIB_PATH=$(SHLR)/wind/

-include ../../global.mk
-include ../../../global.mk
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/cons -lr_cons
LDFLAGS+=-L$(LTOP)/parse -lr_parse
LDFLAGS+=-L$(LTOP)/anal -lr_anal
LDFLAGS+=-L$(LTOP)/reg -lr_reg
LDFLAGS+=-L$(LTOP)/bp -lr_bp
LDFLAGS+=-L$(LTOP)/io -lr_io

LDFLAGS+=-L$(SHLR)/wind -lr_wind

OBJ_WIND=debug_wind.o 

STATIC_OBJ+=${OBJ_WIND}
TARGET_WIND=debug_wind.${EXT_SO}

ALL_TARGETS+=${TARGET_WIND}

${TARGET_WIND}: ${OBJ_WIND}
	${CC_LIB} $(call libname,debug_wind) ${OBJ_WIND} ${CFLAGS} ${LDFLAGS}
