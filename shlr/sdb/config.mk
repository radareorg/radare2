DESTDIR?=
PREFIX?=/usr

SDBVER=0.7.1

INSTALL=install
INSTALL_DIR=$(INSTALL) -d
INSTALL_DATA=$(INSTALL) -m 644
INSTALL_PROGRAM=$(INSTALL) -m 755
INSTALL_SCRIPT=$(INSTALL) -m 755
INSTALL_MAN=$(INSTALL) -m 444
INSTALL_LIB=$(INSTALL) -c

CFLAGS_STD?=-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
#CFLAGS+=-Wno-initializer-overrides
CFLAGS+=${CFLAGS_STD}

# Hack to fix clang warnings
CFLAGS+=$(shell gcc -v 2>&1 | grep -q LLVM && echo '-Wno-initializer-overrides')
CFLAGS+=-Wall
#CFLAGS+=-O3
#CFLAGS+=-ggdb -g -Wall -O0

HAVE_VALA=#$(shell valac --version 2> /dev/null)
# This is hacky
HOST_CC?=gcc
RANLIB?=ranlib
OS?=$(shell uname)
ARCH?=$(shell uname -m)

ifeq (${OS},w32)
WCP?=i386-mingw32
CC=${WCP}-gcc
AR?=${WCP}-ar
CFLAGS_SHARED?=-fPIC
EXEXT=.exe
else
CFLAGS_SHARED?=-fPIC
# -fvisibility=hidden
AR?=ar
CC?=gcc
EXEXT=
endif

# create .d files
CFLAGS+=-MMD

ifeq (${OS},Darwin)
SOEXT=dylib
SOVER=dylib
LDFLAGS+=-dynamic
LDFLAGS_SHARED?=-fPIC -shared
 ifeq (${ARCH},i386)
   #CC+=-arch i386 
   CC+=-arch x86_64
 endif
else
SOVERSION=0
SOEXT=so
SOVER=${SOEXT}.${SDBVER}
LDFLAGS_SHARED?=-fPIC -shared
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
