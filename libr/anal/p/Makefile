include ../../config.mk


CFLAGS+=-I../../include -I../arch -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lr_util -L../../anal -lr_anal -L../../reg -lr_reg
LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS} ;

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=x86_im.mk x86_udis.mk x86_simple.mk ppc.mk arm.mk avr.mk csr.mk dalvik.mk sh.mk ebc.mk gb.mk
include $(ARCHS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all:
.PHONY: all
endif
