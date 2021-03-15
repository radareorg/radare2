include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I../../include -I../arch -Wall -shared $(PIC_CFLAGS) ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lr_util -L../../anal -lr_anal -L../../reg -lr_reg -L../../crypto -lr_crypto
LDFLAGS+=${LINK}

CURDIR=

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=null.mk ppc_gnu.mk ppc_cs.mk arm_gnu.mk avr.mk xap.mk dalvik.mk sh.mk ebc.mk gb.mk malbolge.mk ws.mk h8300.mk cr16.mk v850.mk v850_gnu.mk msp430.mk sparc_gnu.mk sparc_cs.mk x86_cs.mk cris.mk 6502.mk snes.mk riscv.mk vax.mk xtensa.mk rsp.mk mcore.mk tricore.mk
include $(ARCHS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
