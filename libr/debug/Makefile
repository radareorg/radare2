include ../config.mk

NAME=r_debug
DEPS=r_reg r_anal r_bp r_util r_io r_parse r_cons r_db r_syscall r_hash
CFLAGS+=-DCORELIB

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

OBJS=signal.o map.o trace.o arg.o debug.o plugin.o snap.o
OBJS+=pid.o reg.o desc.o esil.o ${STATIC_OBJS} 

ifeq (${OSTYPE},darwin)
OBJS+= p/${NATIVE_OBJS}
endif
ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux android))
OBJS+= p/${NATIVE_OBJS}		
endif

plugins:
	cd p && ${MAKE} all

ios:
	cd ../.. ; sys/rebuild.sh iosdbg

include ../rules.mk

libs: ${LIBSO} ${LIBAR}
.PHONY: foo plugins tests libs
