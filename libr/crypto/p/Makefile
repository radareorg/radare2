include ../../config.mk
include ../../../mk/platform.mk

LINK+=-L../../util -lr_util
LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
CFLAGS+=-I../../include
#ALGOS=aes.mk aes_cbc.mk
include $(ALGOS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
