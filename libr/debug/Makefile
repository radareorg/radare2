include ../config.mk

NAME=r_debug
R2DEPS=r_reg r_anal r_bp r_io r_cons r_syscall r_arch
R2DEPS+=r_socket r_flag r_util r_egg r_muta r_esil r_bin
CFLAGS+=-DR2_PLUGIN_INCORE

foo:
	@${MAKE} libs
	@${MAKE} plugins

include ../config.mk
include ${STATIC_DEBUG_PLUGINS}

# Enable pure-MACH debugging by default.
# The ptrace one will be deprecated at some point
XNU_USE_PTRACE?=0
CFLAGS+=-DXNU_USE_PTRACE=$(XNU_USE_PTRACE)

STATIC_OBJS=$(subst ..,p/..,$(subst debug_,p/debug_,$(STATIC_OBJ)))

OBJS=dsignal.o dmap.o trace.o arg.o debug.o plugin.o snap.o dsession.o
OBJS+=pid.o dreg.o ddesc.o desil.o ${STATIC_OBJS}

ifeq (${OSTYPE},darwin)
ifneq (${NATIVE_OBJS},)
OBJS+= p/${NATIVE_OBJS}
endif
endif


ifeq ($(OSTYPE),windows)
OBJS+=$(addprefix p/,$(NATIVE_OBJS))
endif
ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux android))
CFLAGS+=-I../bin/format/elf
OBJS+=$(addprefix p/,$(NATIVE_OBJS))
endif

ifneq (${COREDUMP_OBJS},)
ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux))
OBJS+= p/${COREDUMP_OBJS}
endif
endif

ifneq (,$(findstring bsd,$(OSTYPE))$(findstring dragonfly,$(OSTYPE)))
ifneq (${NATIVE_OBJS},)
OBJS+=$(addprefix p/,$(NATIVE_OBJS))
endif
endif

plugins:
	$(MAKE) -C p all

ios:
	cd ../.. && sys/rebuild.sh iosdbg

include ../rules.mk
include ../util/deps.mk

libs: ${LIBSO} ${LIBAR}

.PHONY: foo plugins tests libs ios
