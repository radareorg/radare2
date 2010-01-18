RELEASE=1
DESTDIR=
OSTYPE?=gnulinux

COMPILER?=gcc
#COMPILER=mingw32-gcc
#tcc

# verbose error messages everywhere
STATIC_DEBUG=0
# getenv("LIBR_RTDEBUG");
RUNTIME_DEBUG?=1

ifeq (${RELEASE},1)
PREFIX=/usr/local
else
PREFIX=${PWD}/prefix
VERSION=`date '+%Y%m%d'`
endif

LIBDIR=${PREFIX}/lib

-include config-user.mk
-include ../config-user.mk
-include ../../config-user.mk

-include mk/${COMPILER}.mk
-include ../mk/${COMPILER}.mk
-include ../../mk/${COMPILER}.mk
