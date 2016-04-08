ifeq ($(_INCLUDE_GLOBAL_MK_),)
_INCLUDE_GLOBAL_MK_=1
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

ifndef USE_GIT_URLS
GIT_PREFIX=https://
else
GIT_PREFIX=git://
endif

# verbose error messages everywhere
STATIC_DEBUG=0

PREFIX=/usr/local

rmdblslash=$(subst //,/,$(subst //,/,$(subst /$$,,$1)))

LIBDIR=${PREFIX}/lib
WWWROOT=${DATADIR}/radare2/${VERSION}/www

.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

.c.o:
ifneq ($(SILENT),)
	@echo "CC $(shell basename $<)"
endif
	$(CC) -c $(CFLAGS) -o $@ $<

-include $(TOP)/config-user.mk
-include $(TOP)/mk/platform.mk
-include $(TOP)/mk/${COMPILER}.mk
endif
