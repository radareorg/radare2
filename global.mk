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
SPRJ:=$(TOP)/subprojects

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
ifeq ($(SILENT),)
	$(CC) -c $(CFLAGS) -w -o $@ $<
else
	#@echo "[$(shell $(LIBR)/count.sh)] CC $<"
	@echo "[$(shell basename `pwd`)] CC $<"
	@$(CC) -c $(CFLAGS) -w -o $@ $<
endif

-include $(TOP)/config-user.mk
-include $(TOP)/mk/platform.mk
-include $(TOP)/mk/${COMPILER}.mk

WWWROOT=$(DATADIR)/radare2/${VERSION}/www
PANELS=$(DATADIR)/radare2/${VERSION}/panels
endif

## global sdb stuff

USE_SDBTOOL=0
SDBPATH=$(LTOP)/../subprojects/sdb/
ifeq ($(BUILD_OS),windows)
BUILD_EXT_EXE=.exe
else
BUILD_EXT_EXE=
endif

SDB=$(SDBPATH)/sdb${BUILD_EXT_EXE}
SDBTOOL=$(SDBPATH)/sdb${BUILD_EXT_EXE} -r
