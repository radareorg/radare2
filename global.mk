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

rmdblslash=$(subst //,/,$(subst //,/,$(subst /$$,,$1)))

.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

.c.o:
ifneq ($(SILENT),)
	@echo "[$(shell $(LIBR)/count.sh)] CC $<"
	@$(CC) -c $(CFLAGS) -o $@ $<
else
	$(CC) -c $(CFLAGS) -o $@ $<
endif

-include $(TOP)/config-user.mk
-include $(TOP)/mk/platform.mk
-include $(TOP)/mk/${COMPILER}.mk

WWWROOT=${DATADIR}/radare2/${VERSION}/www
endif
