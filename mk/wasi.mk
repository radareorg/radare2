WASI_SDK=$(HOME)/Downloads/wasi/wasi-sdk-20.0
WASI_SYSROOT=$(HOME)/Downloads/wasi/wasi-sysroot-20.0

ifeq (${_INCLUDE_MK_GCC_},)
_INCLUDE_MK_GCC_=1
EXT_EXE=.wasm
EXT_SO=.o
WITH_LIBS=0
EXT_AR=a
CC=$(WASI_SDK)/bin/clang --sysroot=$(WASI_SYSROOT) -DHAVE_PTHREAD=0 -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN -DHAVE_PTY=0
# -lc-printscan-long-double
AR=$(WASI_SDK)/bin/ar
LINK=
RANLIB=$(WASI_SDK)/bin/ranlib
ONELIB=0
CC_AR=$(AR) q ${LIBAR}
PARTIALLD=$(CC) -nostdlib -Wl,--whole-archive -Wl,--no-entry
PIC_CFLAGS=-fPIC
CFLAGS+=-MD -DR2__UNIX__=1
CFLAGS_INCLUDE=-I
LDFLAGS_LINK=-l
LDFLAGS_LINKPATH=-L
CFLAGS_OPT0=-O0
CFLAGS_OPT1=-O1
CFLAGS_OPT2=-O2
CFLAGS_OPT3=-O3
CFLAGS_DEBUG=-g

ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif

LDFLAGS_LIB=-shared
LDFLAGS_SONAME=-DA_

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
endif
