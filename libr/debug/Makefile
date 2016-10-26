include ../config.mk

NAME=r_debug
DEPS=r_reg r_anal r_bp r_io r_parse r_cons r_syscall r_hash r_flag r_util 
DEPS+=r_socket
CFLAGS+=-DCORELIB

ifeq ($(OSTYPE),bsd)
LDFLAGS=-lkvm
endif

#SDBPATH=../../shlr/sdb/src/
#SDBLIB=${SDBPATH}/libsdb.a
#LINK+=${SDBLIB}

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
OBJS+=pid.o dreg.o ddesc.o esil.o ${STATIC_OBJS} 

ifeq (${OSTYPE},darwin)
OBJS+= p/${NATIVE_OBJS}
endif

ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux android))
CFLAGS+=-I../bin/format/elf
OBJS+=$(addprefix p/,$(NATIVE_OBJS))
endif

ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux))
OBJS+= p/${COREDUMP_OBJS}	
endif

plugins:
	cd p && ${MAKE} all

ios:
	cd ../.. ; sys/rebuild.sh iosdbg

include ../rules.mk

libs: ${LIBSO} ${LIBAR}
.PHONY: foo plugins tests libs
