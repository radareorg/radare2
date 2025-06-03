include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I../../include -I../arch -Wall -shared $(PIC_CFLAGS) ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lr_util -L../../anal -lr_anal -L../../reg -lr_reg -L../../muta -lr_muta
LDFLAGS+=${LINK}

CURDIR=

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
include $(ANAL_PLUGINS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
