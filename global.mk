ifeq ($(_INCLUDE_GLOBAL_MK_),)
_INCLUDE_GLOBAL_MK_=1
RELEASE=1
DESTDIR=

TOP:=$(dir $(lastword $(MAKEFILE_LIST)))
LTOP:=$(TOP)/libr

ifeq ($(MAKEFLAGS),s)
SILENT=1
else
SILENT=
endif

.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

.c.o:
ifneq ($(SILENT),)
	@echo CC $<
endif
	$(CC) -c $(CFLAGS) -o $@ $<

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

-include $(TOP)/config-user.mk
-include $(TOP)/mk/${COMPILER}.mk
endif
