include ../../global.mk

NAME=r_asm
R2DEPS=r_syscall r_util r_esil r_muta
R2DEPS+=r_flag r_cons r_reg r_arch
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch/include -Iarch
CFLAGS+=-I../../shlr # for spp only
CURDIR=p/

include $(TOP)/libr/config.mk

LDFLAGS+=${CS_LDFLAGS}
include $(STOP)/java/deps.mk

.PHONY: alle plugins

alle:
	$(MAKE) gperfs
	$(MAKE) plugins

SDB_PATH=../../../subprojects/sdb
SDB=$(SDB_PATH)/sdb

gperfs:
	PATH=$(SDB_PATH):$$PATH $(MAKE) -C d all
	PATH=$(SDB_PATH):$$PATH cd d && for a in *.sdb ; do test $$a -nt `echo $$a.c|sed -e 's,.sdb,,'`; if [ $$? = 0 ]; then $(SDB) -t -C $$a ; fi ; done

plugins: ${LIBSO} ${LIBAR}
	$(MAKE) -C d all
	$(MAKE) -C p all

alle2:
	${MAKE} -C d all
	${MAKE} -C p all
	${MAKE} $(LIBSO)
	${MAKE} $(LIBAR)

EXTRA_CLEAN=doclean
$(EXTRA_CLEAN):
	$(MAKE) -C d clean
	$(MAKE) -C p clean
	rm -f `find arch/| grep '\.o$$'`

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))

# include ${STATIC_PARSE_PLUGINS}
# STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o acode.o aop.o agperf.o filter.o parse.o
OBJS+=${SHARED2_OBJ}


ifeq ($(HAVE_GPERF),1)
OBJS+=d/6502.o
OBJS+=d/8051.o
OBJS+=d/LH5801.o
OBJS+=d/arc.o
OBJS+=d/gb.o
OBJS+=d/evm.o
OBJS+=d/arm.o
OBJS+=d/cosmac.o
OBJS+=d/avr.o
OBJS+=d/chip8.o
OBJS+=d/java.o
OBJS+=d/lm32.o
OBJS+=d/m68k.o
OBJS+=d/mips.o
OBJS+=d/tricore.o
OBJS+=d/s390.o
OBJS+=d/msp430.o
OBJS+=d/pic18c.o
OBJS+=d/ppc.o
OBJS+=d/riscv.o
OBJS+=d/sh.o
OBJS+=d/sparc.o
OBJS+=d/v810.o
OBJS+=d/v850.o
OBJS+=d/x86.o
OBJS+=d/z80.o
endif

include $(TOP)/libr/rules.mk
