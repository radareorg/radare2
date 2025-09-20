include ../config.mk

NAME=r_egg
R2DEPS=r_asm r_syscall r_util
R2DEPS+=r_flag r_cons r_reg r_arch
R2DEPS+=r_esil r_anal r_muta r_search

OBJS=egg.o egg_lang.o
OBJS+=emit_x86.o
OBJS+=emit_arm.o
OBJS+=emit_a64.o
OBJS+=emit_x64.o
OBJS+=emit_esil.o
OBJS+=emit_trace.o
OBJS+=egg_cfile.o

myall:
	$(MAKE) -C p/sc
	$(MAKE) libs
myclean:
	$(MAKE) -C p/sc clean

EXTRA_CLEAN+=myclean

libs: $(LIBSO) $(LIBAR)

P=p/
include $(STATIC_EGG_PLUGINS)
include $(STOP)/java/deps.mk

ifneq (${STATIC_OBJ},)
OBJS+=$(subst ..,${P}..,$(subst egg_,${P}egg_,$(STATIC_OBJ)))
endif

include ../rules.mk
