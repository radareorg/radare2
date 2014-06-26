ifeq ($(_INCLUDE_GLOBAL_MK_),)
_INCLUDE_GLOBAL_MK_=1
RELEASE=1
DESTDIR=
COMPILER?=gcc

TOP:=$(dir $(lastword $(MAKEFILE_LIST)))
LTOP:=$(TOP)/libr
STOP:=$(TOP)/shlr
BTOP:=$(TOP)/binr

ifeq ($(MAKEFLAGS),s)
SILENT=1
else
SILENT=
endif

# verbose error messages everywhere
STATIC_DEBUG=0

ifeq (${RELEASE},1)
PREFIX=/usr/local
else
PREFIX=${PWD}/prefix
VERSION=`date '+%Y%m%d'`
endif

rmdblslash=$(subst //,/,$(subst //,/,$(subst /$$,,$1)))

PFX=${DESTDIR}${PREFIX}
MDR=${DESTDIR}${MANDIR}

LIBDIR=${PREFIX}/lib
WWWROOT=${DATADIR}/radare2/${VERSION}/www

.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

.c.o:
ifneq ($(SILENT),)
	@echo CC $(shell basename $<)
endif
	$(CC) -c $(CFLAGS) -o $@ $<

-include $(TOP)/config-user.mk
-include $(TOP)/mk/${COMPILER}.mk
endif
