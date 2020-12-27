PREFIX?=/usr
BINDIR=${PREFIX}/bin
LIBDIR=${PREFIX}/lib
DATADIR=${PREFIX}/share
INCDIR=${PREFIX}/include
VAPIDIR=${DATADIR}/vala/vapi/
MANDIR=${DATADIR}/man/man1

SDBVER=1.6.0

BUILD_MEMCACHE=0

INSTALL?=install

ifeq ($(INSTALL),cp)
INSTALL_DIR=mkdir -p
INSTALL_DATA=cp -f
INSTALL_PROGRAM=cp -f
INSTALL_SCRIPT=cp -f
INSTALL_MAN=cp -f
INSTALL_LIB=cp -f
else
INSTALL_DIR=$(INSTALL) -d
INSTALL_DATA=$(INSTALL) -m 644
INSTALL_PROGRAM=$(INSTALL) -m 755
INSTALL_SCRIPT=$(INSTALL) -m 755
INSTALL_MAN=$(INSTALL) -m 444
INSTALL_LIB=$(INSTALL) -c
endif

# link time optimization
#CFLAGS_STD=-std=gnu99 -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L -flto -O2

CFLAGS_STD=-std=gnu99 -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
#CFLAGS+=-Wno-initializer-overrides
CFLAGS+=${CFLAGS_STD}

# Hack to fix clang warnings
ifeq ($(CC),cc)
CFLAGS+=$(shell gcc -v 2>&1 | grep -q LLVM && echo '-Wno-initializer-overrides')
endif
CFLAGS+=-Wall
CFLAGS+=-Wsign-compare
# some old gcc doesnt support this
# CFLAGS+=-Wmissing-field-initializers
#CFLAGS+=-O3
CFLAGS+=-g -Wall -O0
#CFLAGS+=-g
#LDFLAGS+=-g -flto

HAVE_VALA=#$(shell valac --version 2> /dev/null)
# This is hacky
HOST_CC?=gcc
RANLIB?=ranlib
OS=$(shell uname)
OSTYPE?=$(shell uname -s)
ARCH?=$(shell uname -m)

AR?=ar
CC?=gcc
EXT_EXE=
EXT_SO=.so

ifneq (,$(findstring MINGW32,${OSTYPE}))
OS=w32
CC=gcc
else
ifeq (${OS},w32)
WCP?=i386-mingw32
CC=${WCP}-gcc
AR?=${WCP}-ar
endif
endif

#LDFLAGS_SHARED?=-fPIC -shared
LDFLAGS_SHARED?=-shared

ifeq (${OS},w32)
EXT_EXE=.exe
EXT_SO=.dll
LDFLAGS_SHARED=-shared
endif

# create .d files
ifeq (,$(findstring tcc,${CC}))
CFLAGS+=-MMD
else
CFLAGS+=-MD
endif

ifeq (${OS},w32)
OSTYPE=MINGW32
endif

ifneq (,$(findstring MINGW,${OSTYPE})$(findstring MSYS,${OSTYPE})$(findstring CYGWIN,${OSTYPE}))
EXT_SO=dll
SOVER=${EXT_SO}
CFLAGS+=-DUNICODE -D_UNICODE
else
EXT_SO=so
SOVER=${EXT_SO}.${SDBVER}
endif
ifeq (${OS},Darwin)
EXT_SO=dylib
SOVER=dylib
LDFLAGS+=-dynamic
LDFLAGS_SHARED+=-dynamiclib
  ifeq (${ARCH},i386)
#CC+=-arch i386
CC+=-arch x86_64
  endif
else
  ifneq (,$(findstring CYGWIN,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
LDFLAGS_SHARED?=-shared
  else
    ifneq (,$(findstring MINGW32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
    else
CFLAGS+=-fPIC
SOVERSION=0
LDFLAGS_SHARED?=-fPIC 
    endif
  endif
LDFLAGS_SHARED+=-Wl,-soname,libsdb.so.$(SOVERSION)
endif

ifeq ($(MAKEFLAGS),s)
SILENT=1
else
SILENT=
endif

ifneq (${SDB_CONFIG},)
include ${SDB_CONFIG}
endif
