DESTDIR?=
PREFIX?=/usr

SDBVER=0.9.2

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

CFLAGS_STD?=-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
#CFLAGS+=-Wno-initializer-overrides
CFLAGS+=${CFLAGS_STD}

# Hack to fix clang warnings
ifeq ($(CC),cc)
CFLAGS+=$(shell gcc -v 2>&1 | grep -q LLVM && echo '-Wno-initializer-overrides')
endif
CFLAGS+=-Wall
#CFLAGS+=-O3
#CFLAGS+=-ggdb -g -Wall -O0
CFLAGS+=-g
LDFLAGS+=-g

HAVE_VALA=#$(shell valac --version 2> /dev/null)
# This is hacky
HOST_CC?=gcc
RANLIB?=ranlib
OS?=$(shell uname)
OSTYPE?=$(shell uname -s)
ARCH?=$(shell uname -m)

AR?=ar
CC?=gcc
EXEXT=
SOEXT=.so

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

LDFLAGS_SHARED?=-fPIC -shared

ifeq (${OS},w32)
EXEXT=.exe
SOEXT=.dll
endif

# create .d files
CFLAGS+=-MMD

ifeq (${OS},Darwin)
SOEXT=dylib
SOVER=dylib
LDFLAGS+=-dynamic
ifeq (${ARCH},i386)
#CC+=-arch i386
CC+=-arch x86_64
endif
else
ifneq (,$(findstring CYGWIN,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
SOEXT=dll
SOVER=${SOEXT}
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring MINGW32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
SOEXT=dll
SOVER=${SOEXT}
else
CFLAGS+=-fPIC
SOVERSION=0
SOEXT=so
SOVER=${SOEXT}.${SDBVER}
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
