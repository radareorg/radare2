include ../config.mk

EXTRA_TARGETS+=do
EXTRA_CLEAN=doclean

NAME=r_anal
R2DEPS=r_util r_reg r_syscall r_search r_cons r_flag r_hash r_crypto r_parse
CFLAGS:=-I.. -I$(LTOP)/asm/arch/include -DR2_PLUGIN_INCORE -Iarch -I$(TOP)/shlr $(CFLAGS)

LDFLAGS+=${BN_LIBS}

CURDIR=p/

include p/capstone.mk
LDFLAGS+=$(CS_LDFLAGS)
include $(STOP)/java/deps.mk
LDFLAGS+=$(LINK)

.PHONY: all main plugins libs ${EXTRA_CLEAN}

main:
	$(MAKE) -C d
	$(MAKE) all

plugins: ${LIBSO} ${LIBAR}
	@$(MAKE) -C p all

include ${STATIC_ANAL_PLUGINS}
include ${STATIC_ESIL_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/anal/p/,$(STATIC_OBJ))
OBJLIBS=meta.o reflines.o op.o fcn.o bb.o var.o block.o
OBJLIBS+=cond.o value.o cc.o class.o diff.o type.o type_pdb.o dwarf_process.o
OBJLIBS+=hint.o anal.o data.o xrefs.o esil.o sign.o esil_plugin.o
OBJLIBS+=esil_handler.o switch.o cycles.o esil_dfg.o esil_cfg.o
OBJLIBS+=esil_stats.o esil_trace.o flirt.o labels.o
OBJLIBS+=pin.o vtable.o rtti.o codemeta.o anplugs.o global.o
OBJLIBS+=rtti_msvc.o rtti_itanium.o jmptbl.o function.o

OBJS=${STATIC_OBJS} ${OBJLIBS} ${ASMOBJS}
ifeq ($(HAVE_GPERF),1)
OBJS+=d/cc-arm-16.o
OBJS+=d/cc-arm-32.o
OBJS+=d/cc-arm-64.o
OBJS+=d/cc-avr-8.o
OBJS+=d/cc-hexagon-32.o
OBJS+=d/cc-m68k-32.o
OBJS+=d/cc-mips-32.o
OBJS+=d/cc-mips-64.o
OBJS+=d/cc-ppc-32.o
OBJS+=d/cc-ppc-64.o
OBJS+=d/cc-riscv-64.o
OBJS+=d/cc-s390-64.o
OBJS+=d/cc-sparc-32.o
OBJS+=d/cc-v850-32.o
OBJS+=d/cc-x86-16.o
OBJS+=d/cc-x86-32.o
OBJS+=d/cc-x86-64.o
OBJS+=d/cc-xtensa-32.o
OBJS+=d/spec.o
OBJS+=d/types-16.o
OBJS+=d/types-32.o
OBJS+=d/types-64.o
OBJS+=d/types-android.o
OBJS+=d/types-arm-ios-16.o
OBJS+=d/types-arm-ios-32.o
OBJS+=d/types-arm-ios-64.o
OBJS+=d/types-darwin.o
OBJS+=d/types-linux.o
OBJS+=d/types-x86-macos-64.o
#OBJS+=d/types-windows.o
#OBJS+=d/types-x86-windows-32.o
#OBJS+=d/types-x86-windows-64.o
OBJS+=d/types.o
endif

test tests: tests-esil

tests-esil:
	cd ../../test && sh run_tests.sh t.esil

.PHONY: do doclean

do:
	$(MAKE) -C ../asm/arch/arm/v35arm64
	$(MAKE) -C d

doclean:
	$(MAKE) -C d clean

include $(LTOP)/rules.mk
