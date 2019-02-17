ifeq (${_INCLUDE_MK_GCC_},)
_INCLUDE_MK_GCC_=1
EXT_EXE=.js
EXT_SO=.bc
EXT_AR=a
CC=emcc
AR=emar
LINK=
RANLIB=emranlib
ONELIB=0
CC_AR=emar q ${LIBAR}
PARTIALLD=emcc -emit-llvm -nostdlib -Wl,--whole-archive
PIC_CFLAGS=-fPIC
CFLAGS+=-MD
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
LDFLAGS_SONAME=-Wl,-soname=

CC_LIB=${CC} ${LDFLAGS_LIB} -o ${LIBSO}
endif
