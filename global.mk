RELEASE=1
DESTDIR=

COMPILER?=gcc
#COMPILER=maemo
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

PFX=${DESTDIR}${PREFIX}
MDR=${DESTDIR}${MANDIR}

LIBDIR=${PREFIX}/lib

-include config-user.mk
-include ../config-user.mk
-include ../../config-user.mk
-include ../../../config-user.mk

-include mk/${COMPILER}.mk
-include ../mk/${COMPILER}.mk
-include ../../mk/${COMPILER}.mk
-include ../../../mk/${COMPILER}.mk
