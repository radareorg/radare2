include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
LDFLAGS+=-L../../util -L../../flag
ifeq ($(CC),cccl)
LDFLAGS+=${LINK} -llibr_flag -llibr_util
else
LDFLAGS+=${LINK} -lr_flag -lr_util
endif

CURDIR=

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=sparc_gnu.mk java.mk arm_gnu.mk
ARCHS+=x86_as.mk x86_nz.mk cris_gnu.mk arc.mk
ARCHS+=ppc_as.mk x86_nasm.mk avr.mk
ARCHS+=sh.mk tms320.mk ebc.mk nds32.mk
ARCHS+=cr16.mk v850.mk vax.mk jdh8.mk riscv.mk
ARCHS+=lm32.mk mcore.mk stm8.mk 8051.mk
# ARCHS+=loongarch_gnu.mk
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
