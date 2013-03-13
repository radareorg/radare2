DESTDIR?=
PREFIX?=/usr

VERSION=0.5

CFLAGS+=-DVERSION=\"${VERSION}\"

CFLAGS+=-Wall
#CFLAGS+=-O3
#CFLAGS+=-ggdb -g -Wall -O0

HAVE_VALA=$(shell valac --version)
# This is hacky
OS=$(shell uname)
ARCH=$(shell uname -m)
ifeq (${OS},Darwin)
SOEXT=dylib
LDFLAGS+=-dynamic
 ifeq (${ARCH},i386)
   CC+=-arch i386 -arch x86_64
 endif
else
SOEXT=so
endif
RANLIB?=ranlib
EXEXT=
