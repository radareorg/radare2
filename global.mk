ifeq ($(_INCLUDE_GLOBAL_MK_),)
_INCLUDE_GLOBAL_MK_=1
DESTDIR=
COMPILER?=gcc

SPACE:=
SPACE+=
ifneq (,$(findstring $(SPACE),$(PREFIX)))
$(error PREFIX cannot contain spaces)
endif
ifneq (,$(findstring $(SPACE),$(shell pwd)))
$(error Current working directory cannot contain spaces)
endif

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

rmdblslash=$(subst //,/,$(subst //,/,$(subst /$$,,$1)))

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

WWWROOT=${DATADIR}/radare2/${VERSION}/www
endif
